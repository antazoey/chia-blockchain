from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from time import monotonic
from typing import Optional

from chia_rs import (
    DONT_VALIDATE_SIGNATURE,
    MEMPOOL_MODE,
    AugSchemeMPL,
    BlockBuilder,
    Coin,
    CoinSpend,
    ConsensusConstants,
    G2Element,
    SpendBundle,
    get_flags_for_height_and_constants,
    run_block_generator2,
    solution_generator_backrefs,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32, uint64

from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.full_node.eligible_coin_spends import (
    IdenticalSpendDedup,
    SingletonFastForward,
    SkipDedup,
)
from chia.full_node.fee_estimation import FeeMempoolInfo, MempoolInfo, MempoolItemInfo
from chia.full_node.fee_estimator_interface import FeeEstimatorInterface
from chia.types.blockchain_format.serialized_program import SerializedProgram
from chia.types.clvm_cost import CLVMCost
from chia.types.generator_types import NewBlockGenerator
from chia.types.internal_mempool_item import InternalMempoolItem
from chia.types.mempool_item import MempoolItem
from chia.util.batches import to_batches
from chia.util.db_wrapper import SQLITE_MAX_VARIABLE_NUMBER
from chia.util.errors import Err

log = logging.getLogger(__name__)

# Maximum number of mempool items that can be skipped (not considered) during
# the creation of a block bundle. An item is skipped if it won't fit in the
# block we're trying to create.
MAX_SKIPPED_ITEMS = 10

# Threshold after which we stop including mempool items with fast-forward or
# dedup spends during the creation of a block generator. We do that to avoid
# spending too much time on potentially expensive items.
PRIORITY_TX_THRESHOLD = 3

# Typical cost of a standard XCH spend. It's used as a heuristic to help
# determine how close to the block size limit we're willing to go.
MIN_COST_THRESHOLD = 6_000_000

# We impose a limit on the fee a single transaction can pay in order to have the
# sum of all fees in the mempool be less than 2^63. That's the limit of sqlite's
# integers, which we rely on for computing fee per cost as well as the fee sum
MEMPOOL_ITEM_FEE_LIMIT = 2**50


@dataclass
class MempoolRemoveInfo:
    items: list[InternalMempoolItem]
    reason: MempoolRemoveReason


@dataclass
class MempoolAddInfo:
    removals: list[MempoolRemoveInfo]
    error: Optional[Err]


class MempoolRemoveReason(Enum):
    CONFLICT = 1
    BLOCK_INCLUSION = 2
    POOL_FULL = 3
    EXPIRED = 4


class Mempool:
    _db_conn: sqlite3.Connection
    # it's expensive to serialize and deserialize G2Element, so we keep those in
    # this separate dictionary
    _items: dict[bytes32, InternalMempoolItem]

    # the most recent block height and timestamp that we know of
    _block_height: uint32
    _timestamp: uint64

    _total_fee: int
    _total_cost: int

    def __init__(self, mempool_info: MempoolInfo, fee_estimator: FeeEstimatorInterface):
        self._db_conn = sqlite3.connect(":memory:")
        self._items = {}
        self._block_height = uint32(0)
        self._timestamp = uint64(0)
        self._total_fee = 0
        self._total_cost = 0

        with self._db_conn:
            # name means SpendBundle hash
            # assert_height may be NIL
            # the seq field indicates the order of items being added to the
            # mempool. It's used as a tie-breaker for items with the same fee
            # rate
            # TODO: In the future, for the "fee_per_cost" field, opt for
            # "GENERATED ALWAYS AS (CAST(fee AS REAL) / cost) VIRTUAL"
            self._db_conn.execute(
                """CREATE TABLE tx(
                name BLOB,
                cost INT NOT NULL,
                fee INT NOT NULL,
                assert_height INT,
                assert_before_height INT,
                assert_before_seconds INT,
                fee_per_cost REAL,
                seq INTEGER PRIMARY KEY AUTOINCREMENT)
                """
            )
            self._db_conn.execute("CREATE INDEX name_idx ON tx(name)")
            self._db_conn.execute("CREATE INDEX feerate ON tx(fee_per_cost)")
            self._db_conn.execute(
                "CREATE INDEX assert_before ON tx(assert_before_height, assert_before_seconds) "
                "WHERE assert_before_height IS NOT NULL OR assert_before_seconds IS NOT NULL"
            )

            # This table maps coin IDs to spend bundles hashes
            self._db_conn.execute(
                """CREATE TABLE spends(
                coin_id BLOB NOT NULL,
                tx BLOB NOT NULL,
                UNIQUE(coin_id, tx))
                """
            )
            self._db_conn.execute("CREATE INDEX spend_by_coin ON spends(coin_id)")
            self._db_conn.execute("CREATE INDEX spend_by_bundle ON spends(tx)")

        self.mempool_info: MempoolInfo = mempool_info
        self.fee_estimator: FeeEstimatorInterface = fee_estimator

    def __del__(self) -> None:
        self._db_conn.close()

    def _row_to_item(self, row: sqlite3.Row) -> MempoolItem:
        name = bytes32(row[0])
        fee = int(row[2])
        assert_height = row[3]
        assert_before_height = row[4]
        assert_before_seconds = row[5]
        item = self._items[name]

        return MempoolItem(
            item.spend_bundle,
            uint64(fee),
            item.conds,
            name,
            uint32(item.height_added_to_mempool),
            assert_height,
            assert_before_height,
            assert_before_seconds,
            bundle_coin_spends=item.bundle_coin_spends,
        )

    def total_mempool_fees(self) -> int:
        return self._total_fee

    def total_mempool_cost(self) -> CLVMCost:
        return CLVMCost(uint64(self._total_cost))

    def all_items(self) -> Iterator[MempoolItem]:
        with self._db_conn:
            cursor = self._db_conn.execute("SELECT * FROM tx")
            for row in cursor:
                yield self._row_to_item(row)

    def all_item_ids(self) -> list[bytes32]:
        with self._db_conn:
            cursor = self._db_conn.execute("SELECT name FROM tx")
            return [bytes32(row[0]) for row in cursor]

    def items_with_coin_ids(self, coin_ids: set[bytes32]) -> list[bytes32]:
        """
        Returns a list of transaction ids that spend or create any coins with the provided coin ids.
        This iterates over the internal items instead of using a query.
        """

        transaction_ids: list[bytes32] = []

        for transaction_id, item in self._items.items():
            conds = item.conds
            assert conds is not None

            for spend in conds.spends:
                if spend.coin_id in coin_ids:
                    transaction_ids.append(transaction_id)
                    break

                for puzzle_hash, amount, _memo in spend.create_coin:
                    if Coin(spend.coin_id, puzzle_hash, uint64(amount)).name() in coin_ids:
                        transaction_ids.append(transaction_id)
                        break
                else:
                    continue

                break

        return transaction_ids

    def items_with_puzzle_hashes(self, puzzle_hashes: set[bytes32], include_hints: bool) -> list[bytes32]:
        """
        Returns a list of transaction ids that spend or create any coins
        with the provided puzzle hashes (or hints, if enabled).
        This iterates over the internal items instead of using a query.
        """

        transaction_ids: list[bytes32] = []

        for transaction_id, item in self._items.items():
            conds = item.conds
            assert conds is not None

            for spend in conds.spends:
                if spend.puzzle_hash in puzzle_hashes:
                    transaction_ids.append(transaction_id)
                    break

                for puzzle_hash, _amount, memo in spend.create_coin:
                    if puzzle_hash in puzzle_hashes or (include_hints and memo is not None and memo in puzzle_hashes):
                        transaction_ids.append(transaction_id)
                        break
                else:
                    continue

                break

        return transaction_ids

    # TODO: move "process_mempool_items()" into this class in order to do this a
    # bit more efficiently
    def items_by_feerate(self) -> Iterator[MempoolItem]:
        cursor = self._db_conn.execute("SELECT * FROM tx ORDER BY fee_per_cost DESC, seq ASC")
        for row in cursor:
            yield self._row_to_item(row)

    def size(self) -> int:
        cursor = self._db_conn.execute("SELECT COUNT(name) FROM tx")
        row = cursor.fetchone()
        return int(row[0])

    def get_item_by_id(self, item_id: bytes32) -> Optional[MempoolItem]:
        with self._db_conn:
            cursor = self._db_conn.execute("SELECT * FROM tx WHERE name=?", (item_id,))
            row = cursor.fetchone()
            return None if row is None else self._row_to_item(row)

    # TODO: we need a bulk lookup function like this too
    def get_items_by_coin_id(self, spent_coin_id: bytes32) -> Iterator[MempoolItem]:
        cursor = self._db_conn.execute(
            """
            SELECT *
            FROM tx
            WHERE name IN (
                SELECT tx
                FROM spends
                WHERE coin_id = ?
            )
            """,
            (spent_coin_id,),
        )
        for row in cursor:
            yield self._row_to_item(row)

    def get_items_by_coin_ids(self, spent_coin_ids: list[bytes32]) -> list[MempoolItem]:
        items: list[MempoolItem] = []
        for batch in to_batches(spent_coin_ids, SQLITE_MAX_VARIABLE_NUMBER):
            args = ",".join(["?"] * len(batch.entries))
            cursor = self._db_conn.execute(
                f"SELECT * FROM tx WHERE name IN (SELECT tx FROM spends WHERE coin_id IN ({args}))",
                tuple(batch.entries),
            )
            items.extend(self._row_to_item(row) for row in cursor)
        return items

    def get_min_fee_rate(self, cost: int) -> Optional[float]:
        """
        Gets the minimum fpc rate that a transaction with specified cost will need in order to get included.
        """

        if not self.at_full_capacity(cost):
            return 0

        # TODO: make MempoolItem.cost be CLVMCost
        current_cost = self._total_cost

        # Iterates through all spends in increasing fee per cost
        with self._db_conn:
            cursor = self._db_conn.execute("SELECT cost,fee_per_cost FROM tx ORDER BY fee_per_cost ASC, seq DESC")

            item_cost: int
            fee_per_cost: float
            for item_cost, fee_per_cost in cursor:
                current_cost -= item_cost
                # Removing one at a time, until our transaction of size cost fits
                if current_cost + cost <= self.mempool_info.max_size_in_cost:
                    return fee_per_cost

            log.info(
                f"Transaction with cost {cost} does not fit in mempool of max cost {self.mempool_info.max_size_in_cost}"
            )
            return None

    def new_tx_block(self, block_height: uint32, timestamp: uint64) -> MempoolRemoveInfo:
        """
        Remove all items that became invalid because of this new height and
        timestamp. (we don't know about which coins were spent in this new block
        here, so those are handled separately)
        """
        with self._db_conn:
            cursor = self._db_conn.execute(
                "SELECT name FROM tx WHERE assert_before_seconds <= ? OR assert_before_height <= ?",
                (timestamp, block_height),
            )
            to_remove = [bytes32(row[0]) for row in cursor]

        self._block_height = block_height
        self._timestamp = timestamp

        return self.remove_from_pool(to_remove, MempoolRemoveReason.EXPIRED)

    def remove_from_pool(self, items: list[bytes32], reason: MempoolRemoveReason) -> MempoolRemoveInfo:
        """
        Removes an item from the mempool.
        """
        if items == []:
            return MempoolRemoveInfo([], reason)

        removed_items: list[MempoolItemInfo] = []
        if reason != MempoolRemoveReason.BLOCK_INCLUSION:
            for batch in to_batches(items, SQLITE_MAX_VARIABLE_NUMBER):
                args = ",".join(["?"] * len(batch.entries))
                with self._db_conn:
                    cursor = self._db_conn.execute(
                        f"SELECT name, cost, fee FROM tx WHERE name in ({args})", batch.entries
                    )
                    for row in cursor:
                        name = bytes32(row[0])
                        internal_item = self._items[name]
                        item = MempoolItemInfo(int(row[1]), int(row[2]), internal_item.height_added_to_mempool)
                        removed_items.append(item)

        removed_internal_items = [self._items.pop(name) for name in items]

        for batch in to_batches(items, SQLITE_MAX_VARIABLE_NUMBER):
            args = ",".join(["?"] * len(batch.entries))
            with self._db_conn:
                cursor = self._db_conn.execute(
                    f"SELECT SUM(cost), SUM(fee) FROM tx WHERE name in ({args})", batch.entries
                )
                cost_to_remove, fee_to_remove = cursor.fetchone()

                self._db_conn.execute(f"DELETE FROM tx WHERE name in ({args})", batch.entries)
                self._db_conn.execute(f"DELETE FROM spends WHERE tx in ({args})", batch.entries)

            self._total_cost -= cost_to_remove
            self._total_fee -= fee_to_remove
            assert self._total_cost >= 0
            assert self._total_fee >= 0

        if reason != MempoolRemoveReason.BLOCK_INCLUSION:
            info = FeeMempoolInfo(
                self.mempool_info, self.total_mempool_cost(), self.total_mempool_fees(), datetime.now()
            )
            for iteminfo in removed_items:
                self.fee_estimator.remove_mempool_item(info, iteminfo)

        return MempoolRemoveInfo(removed_internal_items, reason)

    def add_to_pool(self, item: MempoolItem) -> MempoolAddInfo:
        """
        Adds an item to the mempool by kicking out transactions (if it doesn't fit), in order of increasing fee per cost
        """

        assert item.fee < MEMPOOL_ITEM_FEE_LIMIT
        assert item.conds is not None
        assert item.cost <= self.mempool_info.max_block_clvm_cost

        removals: list[MempoolRemoveInfo] = []

        # we have certain limits on transactions that will expire soon
        # (in the next 15 minutes)
        block_cutoff = self._block_height + 48
        time_cutoff = self._timestamp + 900
        if (item.assert_before_height is not None and item.assert_before_height < block_cutoff) or (
            item.assert_before_seconds is not None and item.assert_before_seconds < time_cutoff
        ):
            # this lists only transactions that expire soon, in order of
            # lowest fee rate along with the cumulative cost of such
            # transactions counting from highest to lowest fee rate
            cursor = self._db_conn.execute(
                """
                SELECT name,
                    fee_per_cost,
                    SUM(cost) OVER (ORDER BY fee_per_cost DESC, seq ASC) AS cumulative_cost
                FROM tx
                WHERE assert_before_seconds IS NOT NULL AND assert_before_seconds < ?
                    OR assert_before_height IS NOT NULL AND assert_before_height < ?
                ORDER BY cumulative_cost DESC
                """,
                (time_cutoff, block_cutoff),
            )
            to_remove: list[bytes32] = []
            for row in cursor:
                name, fee_per_cost, cumulative_cost = row

                # there's space for us, stop pruning
                if cumulative_cost + item.cost <= self.mempool_info.max_block_clvm_cost:
                    break

                # we can't evict any more transactions, abort (and don't
                # evict what we put aside in "to_remove" list)
                if fee_per_cost > item.fee_per_cost:
                    return MempoolAddInfo([], Err.INVALID_FEE_LOW_FEE)
                to_remove.append(name)

            removals.append(self.remove_from_pool(to_remove, MempoolRemoveReason.EXPIRED))

            # if we don't find any entries, it's OK to add this entry

        if self._total_cost + item.cost > self.mempool_info.max_size_in_cost:
            # pick the items with the lowest fee per cost to remove
            cursor = self._db_conn.execute(
                """SELECT name FROM tx
                WHERE name NOT IN (
                    SELECT name FROM (
                        SELECT name,
                        SUM(cost) OVER (ORDER BY fee_per_cost DESC, seq ASC) AS total_cost
                        FROM tx) AS tx_with_cost
                    WHERE total_cost <= ?)
                """,
                (self.mempool_info.max_size_in_cost - item.cost,),
            )
            to_remove = [bytes32(row[0]) for row in cursor]
            removals.append(self.remove_from_pool(to_remove, MempoolRemoveReason.POOL_FULL))

        with self._db_conn as conn:
            # TODO: In the future, for the "fee_per_cost" field, opt for
            # "GENERATED ALWAYS AS (CAST(fee AS REAL) / cost) VIRTUAL"
            conn.execute(
                "INSERT INTO "
                "tx(name,cost,fee,assert_height,assert_before_height,assert_before_seconds,fee_per_cost) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    item.name,
                    item.cost,
                    item.fee,
                    item.assert_height,
                    item.assert_before_height,
                    item.assert_before_seconds,
                    item.fee / item.cost,
                ),
            )
            all_coin_spends = []
            # item.name is a property
            # only compute its name once (the spend bundle name)
            item_name = item.name
            for coin_id, bcs in item.bundle_coin_spends.items():
                # any FF spend should be indexed by its latest singleton coin
                # ID, this way we'll find it when the singleton is spent
                if bcs.latest_singleton_lineage is not None:
                    all_coin_spends.append((bcs.latest_singleton_lineage.coin_id, item_name))
                else:
                    all_coin_spends.append((coin_id, item_name))
            conn.executemany("INSERT OR IGNORE INTO spends VALUES(?, ?)", all_coin_spends)

        self._items[item_name] = InternalMempoolItem(
            item.spend_bundle, item.conds, item.height_added_to_mempool, item.bundle_coin_spends
        )
        self._total_cost += item.cost
        self._total_fee += item.fee

        info = FeeMempoolInfo(self.mempool_info, self.total_mempool_cost(), self.total_mempool_fees(), datetime.now())
        self.fee_estimator.add_mempool_item(info, MempoolItemInfo(item.cost, item.fee, item.height_added_to_mempool))
        return MempoolAddInfo(removals, None)

    # each tuple holds new_coin_id, current_coin_id, mempool item name
    def update_spend_index(self, spends_to_update: list[tuple[bytes32, bytes32, bytes32]]) -> None:
        with self._db_conn as conn:
            conn.executemany("UPDATE OR REPLACE spends SET coin_id=? WHERE coin_id=? AND tx=?", spends_to_update)

    def at_full_capacity(self, cost: int) -> bool:
        """
        Checks whether the mempool is at full capacity and cannot accept a transaction with size cost.
        """

        return self._total_cost + cost > self.mempool_info.max_size_in_cost

    def create_block_generator(
        self,
        constants: ConsensusConstants,
        height: uint32,
        timeout: float,
    ) -> Optional[NewBlockGenerator]:
        """
        height is needed in case we fast-forward a transaction and we need to
        re-run its puzzle.
        """

        mempool_bundle = self.create_bundle_from_mempool_items(constants, height, timeout)
        if mempool_bundle is None:
            return None

        spend_bundle, additions = mempool_bundle
        removals = spend_bundle.removals()
        log.info(f"Add rem: {len(additions)} {len(removals)}")

        # since the hard fork has activated, block generators are
        # allowed to be serialized with CLVM back-references. We can do that
        # unconditionally.
        start_time = monotonic()
        spends = [(cs.coin, bytes(cs.puzzle_reveal), bytes(cs.solution)) for cs in spend_bundle.coin_spends]
        block_program = solution_generator_backrefs(spends)

        duration = monotonic() - start_time
        log.log(
            logging.INFO if duration < 1 else logging.WARNING,
            f"serializing block generator took {duration:0.2f} seconds "
            f"spends: {len(removals)} additions: {len(additions)}",
        )

        flags = get_flags_for_height_and_constants(height, constants) | MEMPOOL_MODE | DONT_VALIDATE_SIGNATURE

        err, conds = run_block_generator2(
            block_program,
            [],
            constants.MAX_BLOCK_COST_CLVM,
            flags,
            spend_bundle.aggregated_signature,
            None,
            constants,
        )

        # this should not happen. This is essentially an assertion failure
        if err is not None:  # pragma: no cover
            log.error(
                f"Failed to compute block cost during farming: {err} "
                f"height: {height} "
                f"generator: {bytes(block_program).hex()}"
            )
            return None

        assert conds is not None
        assert conds.cost > 0

        return NewBlockGenerator(
            SerializedProgram.from_bytes(block_program),
            [],
            [],
            spend_bundle.aggregated_signature,
            additions,
            removals,
            uint64(conds.cost),
        )

    def create_bundle_from_mempool_items(
        self, constants: ConsensusConstants, height: uint32, timeout: float = 1.0
    ) -> Optional[tuple[SpendBundle, list[Coin]]]:
        cost_sum = 0  # Checks that total cost does not exceed block maximum
        fee_sum = 0  # Checks that total fees don't exceed 64 bits
        processed_spend_bundles = 0
        additions: list[Coin] = []
        # This contains a map of coin ID to a coin spend solution and its
        # isolated cost. We reconstruct it for every bundle we create from
        # mempool items because we deduplicate on the first coin spend solution
        # that comes with the highest fee rate item, and that can change across
        # calls.
        dedup_coin_spends = IdenticalSpendDedup()
        # This contains a map of fast forward eligible singleton puzzle hash to
        # the most recent unspent singleton data, to allow chaining fast forward
        # singleton spends.
        singleton_ff = SingletonFastForward()
        coin_spends: list[CoinSpend] = []
        sigs: list[G2Element] = []
        log.info(f"Starting to make block, max cost: {self.mempool_info.max_block_clvm_cost}")
        bundle_creation_start = monotonic()
        cursor = self._db_conn.execute("SELECT name, fee FROM tx ORDER BY fee_per_cost DESC, seq ASC")
        skipped_items = 0
        for row in cursor:
            name = bytes32(row[0])
            fee = int(row[1])
            item = self._items[name]

            current_time = monotonic()
            if current_time - bundle_creation_start >= timeout:
                log.info(f"exiting early, already spent {current_time - bundle_creation_start:0.2f} s")
                break
            try:
                assert item.conds is not None
                cost = item.conds.cost
                if skipped_items >= PRIORITY_TX_THRESHOLD:
                    # If we've encountered `PRIORITY_TX_THRESHOLD` number of
                    # transactions that don't fit in the remaining block size,
                    # we want to keep looking for smaller transactions that
                    # might fit, but we also want to avoid spending too much
                    # time on potentially expensive ones, hence this shortcut.
                    if any(
                        sd.eligible_for_dedup or sd.eligible_for_fast_forward for sd in item.bundle_coin_spends.values()
                    ):
                        log.info(f"Skipping transaction with dedup or FF spends {item.spend_bundle.name()}")
                        continue

                    unique_coin_spends = []
                    unique_additions = []
                    for spend_data in item.bundle_coin_spends.values():
                        unique_coin_spends.append(spend_data.coin_spend)
                        unique_additions.extend(spend_data.additions)
                    cost_saving = 0
                else:
                    bundle_coin_spends = singleton_ff.process_fast_forward_spends(
                        mempool_item=item, height=height, constants=constants
                    )
                    unique_coin_spends, cost_saving, unique_additions = dedup_coin_spends.get_deduplication_info(
                        bundle_coin_spends=bundle_coin_spends
                    )
                item_cost = cost - cost_saving
                log.info(
                    "Cumulative cost: %d, fee per cost: %0.4f, item cost: %d", cost_sum, fee / item_cost, item_cost
                )
                new_fee_sum = fee_sum + fee
                if new_fee_sum > DEFAULT_CONSTANTS.MAX_COIN_AMOUNT:
                    # Such a fee is very unlikely to happen but we're defensively
                    # accounting for it
                    break  # pragma: no cover
                new_cost_sum = cost_sum + item_cost
                if new_cost_sum > self.mempool_info.max_block_clvm_cost:
                    # Let's skip this item
                    log.info(
                        "Skipping mempool item. Cumulative cost %d exceeds maximum block cost %d",
                        new_cost_sum,
                        self.mempool_info.max_block_clvm_cost,
                    )
                    skipped_items += 1
                    if skipped_items < MAX_SKIPPED_ITEMS:
                        continue
                    # Let's stop taking more items if we skipped `MAX_SKIPPED_ITEMS`
                    break
                coin_spends.extend(unique_coin_spends)
                additions.extend(unique_additions)
                sigs.append(item.spend_bundle.aggregated_signature)
                cost_sum = new_cost_sum
                fee_sum = new_fee_sum
                processed_spend_bundles += 1
                # Let's stop taking more items if we don't have enough cost left
                # for at least `MIN_COST_THRESHOLD` because that would mean we're
                # getting very close to the limit anyway and *probably* won't
                # find transactions small enough to fit at this point
                if self.mempool_info.max_block_clvm_cost - cost_sum < MIN_COST_THRESHOLD:
                    break
            except SkipDedup as e:
                log.info(f"{e}")
                continue
            except Exception as e:
                log.info(f"Exception while checking a mempool item for deduplication: {e}")
                skipped_items += 1
                continue
        if coin_spends == []:
            return None
        log.info(
            f"Cumulative cost of block (real cost should be less) {cost_sum}. Proportion "
            f"full: {cost_sum / self.mempool_info.max_block_clvm_cost}"
        )
        aggregated_signature = AugSchemeMPL.aggregate(sigs)
        agg = SpendBundle(coin_spends, aggregated_signature)
        bundle_creation_end = monotonic()
        duration = bundle_creation_end - bundle_creation_start
        log.log(
            logging.INFO if duration < 1 else logging.WARNING,
            f"create_bundle_from_mempool_items took {duration:0.4f} seconds",
        )
        return agg, additions

    def create_block_generator2(
        self, constants: ConsensusConstants, height: uint32, timeout: float
    ) -> Optional[NewBlockGenerator]:
        fee_sum = 0  # Checks that total fees don't exceed 64 bits
        additions: list[Coin] = []
        removals: list[Coin] = []

        dedup_coin_spends = IdenticalSpendDedup()
        singleton_ff = SingletonFastForward()
        log.info(f"Starting to make block, max cost: {self.mempool_info.max_block_clvm_cost}")
        generator_creation_start = monotonic()
        cursor = self._db_conn.execute("SELECT name, fee FROM tx ORDER BY fee_per_cost DESC, seq ASC")
        builder = BlockBuilder()
        skipped_items = 0
        # the total (estimated) cost of the transactions added so far
        block_cost = 0
        added_spends = 0

        batch_transactions: list[SpendBundle] = []
        batch_additions: list[Coin] = []
        batch_spends = 0
        # this cost only includes conditions and execution cost, not byte-cost
        batch_cost = 0

        for row in cursor:
            current_time = monotonic()
            if current_time - generator_creation_start >= timeout:
                log.info(f"exiting early, already spent {current_time - generator_creation_start:0.2f} s")
                break

            name = bytes32(row[0])
            fee = int(row[1])
            item = self._items[name]
            try:
                assert item.conds is not None
                cost = item.conds.condition_cost + item.conds.execution_cost
                bundle_coin_spends = singleton_ff.process_fast_forward_spends(
                    mempool_item=item, height=height, constants=constants
                )
                unique_coin_spends, cost_saving, unique_additions = dedup_coin_spends.get_deduplication_info(
                    bundle_coin_spends=bundle_coin_spends
                )
                new_fee_sum = fee_sum + fee
                if new_fee_sum > DEFAULT_CONSTANTS.MAX_COIN_AMOUNT:
                    # Such a fee is very unlikely to happen but we're defensively
                    # accounting for it
                    break  # pragma: no cover

                # if adding item would make us exceed the block cost, commit the
                # batch we've built up first, to see if more space may be freed
                # up by the compression
                if block_cost + item.conds.cost - cost_saving > constants.MAX_BLOCK_COST_CLVM:
                    added, done = builder.add_spend_bundles(batch_transactions, uint64(batch_cost), constants)

                    block_cost = builder.cost()
                    if added:
                        added_spends += batch_spends
                        additions.extend(batch_additions)
                        removals.extend([cs.coin for sb in batch_transactions for cs in sb.coin_spends])
                        log.info(
                            f"adding TX batch, additions: {len(batch_additions)} removals: {batch_spends} "
                            f"cost: {batch_cost} total cost: {block_cost}"
                        )
                    else:
                        skipped_items += 1

                    batch_cost = 0
                    batch_transactions = []
                    batch_additions = []
                    batch_spends = 0
                    if done:
                        break

                batch_cost += cost - cost_saving
                batch_transactions.append(SpendBundle(unique_coin_spends, item.spend_bundle.aggregated_signature))
                batch_spends += len(unique_coin_spends)
                batch_additions.extend(unique_additions)
                fee_sum = new_fee_sum
                block_cost += item.conds.cost - cost_saving
            except SkipDedup as e:
                log.info(f"{e}")
                continue
            except Exception as e:
                log.info(f"Exception while checking a mempool item for deduplication: {e}")
                skipped_items += 1
                continue

        if len(batch_transactions) > 0:
            added, _ = builder.add_spend_bundles(batch_transactions, uint64(batch_cost), constants)

            if added:
                added_spends += batch_spends
                additions.extend(batch_additions)
                removals.extend([cs.coin for sb in batch_transactions for cs in sb.coin_spends])
                block_cost = builder.cost()
                log.info(
                    f"adding TX batch, additions: {len(batch_additions)} removals: {batch_spends} "
                    f"cost: {batch_cost} total cost: {block_cost}"
                )

        if removals == []:
            return None

        generator_creation_end = monotonic()
        duration = generator_creation_end - generator_creation_start
        block_program, signature, cost = builder.finalize(constants)
        log.log(
            logging.INFO if duration < 2 else logging.WARNING,
            f"create_block_generator2() took {duration:0.4f} seconds. "
            f"block cost: {cost} spends: {added_spends} additions: {len(additions)}",
        )
        assert block_cost == cost

        return NewBlockGenerator(
            SerializedProgram.from_bytes(block_program),
            [],
            [],
            signature,
            additions,
            removals,
            uint64(block_cost),
        )
