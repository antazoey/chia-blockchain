from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, BinaryIO, Optional, Union

from chia_puzzles_py.programs import SETTLEMENT_PAYMENT, SETTLEMENT_PAYMENT_HASH
from chia_rs import CoinSpend, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from clvm_tools.binutils import disassemble

from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.coin import Coin, coin_as_list
from chia.types.blockchain_format.program import INFINITE_COST, Program, run_with_cost, uncurry
from chia.types.coin_spend import make_spend
from chia.util.bech32m import bech32_decode, bech32_encode, convertbits
from chia.util.errors import Err, ValidationError
from chia.util.streamable import parse_rust
from chia.wallet.conditions import (
    AssertCoinAnnouncement,
    AssertPuzzleAnnouncement,
    Condition,
    ConditionValidTimes,
    CreateCoin,
    parse_conditions_non_consensus,
    parse_timelock_info,
)
from chia.wallet.outer_puzzles import (
    construct_puzzle,
    create_asset_id,
    get_inner_puzzle,
    get_inner_solution,
    match_puzzle,
    solve_puzzle,
)
from chia.wallet.puzzle_drivers import PuzzleInfo, Solver
from chia.wallet.uncurried_puzzle import UncurriedPuzzle, uncurry_puzzle
from chia.wallet.util.compute_hints import compute_spend_hints_and_additions
from chia.wallet.util.puzzle_compression import (
    compress_object_with_puzzles,
    decompress_object_with_puzzles,
    lowest_best_version,
)
from chia.wallet.wallet_spend_bundle import WalletSpendBundle

OfferSummary = dict[Union[int, bytes32], int]

OFFER_MOD = Program.from_bytes(SETTLEMENT_PAYMENT)
OFFER_MOD_HASH = bytes32(SETTLEMENT_PAYMENT_HASH)


def detect_dependent_coin(
    names: list[bytes32], deps: dict[bytes32, list[bytes32]], announcement_dict: dict[bytes32, list[bytes32]]
) -> Optional[tuple[bytes32, bytes32]]:
    # First, we check for any dependencies on coins in the same bundle
    for name in names:
        for dependency in deps[name]:
            for coin, announces in announcement_dict.items():
                if dependency in announces and coin != name:
                    # We found one, now remove it and anything that depends on it (except the "provider")
                    return name, coin
    return None


@dataclass(frozen=True)
class NotarizedPayment(CreateCoin):
    nonce: bytes32 = bytes32.zeros

    @classmethod
    def from_condition_and_nonce(cls, condition: Program, nonce: bytes32) -> NotarizedPayment:
        with_opcode: Program = Program.to((51, condition))  # Gotta do this because the super class is expecting it
        p = CreateCoin.from_program(with_opcode)
        return cls(p.puzzle_hash, p.amount, p.memos, nonce)

    def name(self) -> bytes32:
        return self.to_program().get_tree_hash()


@dataclass(frozen=True, eq=False)
class Offer:
    requested_payments: dict[
        Optional[bytes32], list[NotarizedPayment]
    ]  # The key is the asset id of the asset being requested
    _bundle: WalletSpendBundle
    driver_dict: dict[bytes32, PuzzleInfo]  # asset_id -> asset driver

    # this is a cache of the coin additions made by the SpendBundle (_bundle)
    # ordered by the coin being spent
    _additions: dict[Coin, list[Coin]] = field(init=False, repr=False)
    _hints: dict[bytes32, bytes32] = field(init=False)
    _offered_coins: dict[Optional[bytes32], list[Coin]] = field(init=False, repr=False)
    _final_spend_bundle: Optional[WalletSpendBundle] = field(init=False, repr=False)
    _conditions: Optional[dict[Coin, list[Condition]]] = field(init=False)

    @staticmethod
    def ph() -> bytes32:
        return OFFER_MOD_HASH

    @staticmethod
    def notarize_payments(
        requested_payments: dict[Optional[bytes32], list[CreateCoin]],  # `None` means you are requesting XCH
        coins: list[Coin],
    ) -> dict[Optional[bytes32], list[NotarizedPayment]]:
        # This sort should be reproducible in CLVM with `>s`
        sorted_coins: list[Coin] = sorted(coins, key=Coin.name)
        sorted_coin_list: list[list[Union[bytes32, uint64]]] = [coin_as_list(c) for c in sorted_coins]
        nonce: bytes32 = Program.to(sorted_coin_list).get_tree_hash()

        notarized_payments: dict[Optional[bytes32], list[NotarizedPayment]] = {}
        for asset_id, payments in requested_payments.items():
            notarized_payments[asset_id] = []
            for p in payments:
                notarized_payments[asset_id].append(NotarizedPayment(p.puzzle_hash, p.amount, p.memos, nonce))

        return notarized_payments

    # The announcements returned from this function must be asserted in whatever spend bundle is created by the wallet
    @staticmethod
    def calculate_announcements(
        notarized_payments: dict[Optional[bytes32], list[NotarizedPayment]],
        driver_dict: dict[bytes32, PuzzleInfo],
    ) -> list[AssertPuzzleAnnouncement]:
        announcements: list[AssertPuzzleAnnouncement] = []
        for asset_id, payments in notarized_payments.items():
            if asset_id is not None:
                if asset_id not in driver_dict:
                    raise ValueError("Cannot calculate announcements without driver of requested item")
                settlement_ph: bytes32 = construct_puzzle(driver_dict[asset_id], OFFER_MOD).get_tree_hash()
            else:
                settlement_ph = OFFER_MOD_HASH

            msg: bytes32 = Program.to((payments[0].nonce, [p.as_condition_args() for p in payments])).get_tree_hash()
            announcements.append(AssertPuzzleAnnouncement(asserted_ph=settlement_ph, asserted_msg=msg))

        return announcements

    def __post_init__(self) -> None:
        # Verify that there are no duplicate payments
        for payments in self.requested_payments.values():
            payment_programs: list[bytes32] = [p.name() for p in payments]
            if len(set(payment_programs)) != len(payment_programs):
                raise ValueError("Bundle has duplicate requested payments")

        # Verify we have a type for every kind of asset
        for asset_id in self.requested_payments:
            if asset_id is not None and asset_id not in self.driver_dict:
                raise ValueError("Offer does not have enough driver information about the requested payments")

        # populate the _additions cache
        adds: dict[Coin, list[Coin]] = {}
        hints: dict[bytes32, bytes32] = {}
        max_cost = int(DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM)
        for cs in self._bundle.coin_spends:
            # you can't spend the same coin twice in the same SpendBundle
            assert cs.coin not in adds
            try:
                hinted_coins, cost = compute_spend_hints_and_additions(cs)
                max_cost -= cost
                adds[cs.coin] = [hc.coin for hc in hinted_coins.values()]
                hints = {**hints, **{id: hc.hint for id, hc in hinted_coins.items() if hc.hint is not None}}
            except Exception:
                continue
            if max_cost < 0:
                raise ValidationError(Err.BLOCK_COST_EXCEEDS_MAX, "compute_additions for CoinSpend")
        object.__setattr__(self, "_additions", adds)
        object.__setattr__(self, "_hints", hints)
        object.__setattr__(self, "_conditions", None)

    def conditions(self) -> dict[Coin, list[Condition]]:
        if self._conditions is None:
            conditions: dict[Coin, list[Condition]] = {}
            max_cost = int(DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM)
            for cs in self._bundle.coin_spends:
                try:
                    cost, conds = run_with_cost(cs.puzzle_reveal, max_cost, cs.solution)
                    max_cost -= cost
                    conditions[cs.coin] = parse_conditions_non_consensus(conds.as_iter())
                except Exception:  # pragma: no cover
                    continue
                if max_cost < 0:  # pragma: no cover
                    raise ValidationError(Err.BLOCK_COST_EXCEEDS_MAX, "computing conditions for CoinSpend")
            object.__setattr__(self, "_conditions", conditions)
        assert self._conditions is not None, "self._conditions is None"
        return self._conditions

    def valid_times(self) -> dict[Coin, ConditionValidTimes]:
        return {coin: parse_timelock_info(conditions) for coin, conditions in self.conditions().items()}

    def absolute_valid_times_ban_relatives(self) -> ConditionValidTimes:
        valid_times: ConditionValidTimes = parse_timelock_info(
            [c for conditions in self.conditions().values() for c in conditions]
        )
        if (
            valid_times.max_secs_after_created is not None
            or valid_times.min_secs_since_created is not None
            or valid_times.max_blocks_after_created is not None
            or valid_times.min_blocks_since_created is not None
        ):
            raise ValueError("Offers with relative timelocks are not currently supported")
        return valid_times

    def hints(self) -> dict[bytes32, bytes32]:
        return self._hints

    def additions(self) -> list[Coin]:
        return [c for additions in self._additions.values() for c in additions]

    def removals(self) -> list[Coin]:
        return self._bundle.removals()

    def fees(self) -> int:
        """Unsafe to use for fees validation!!!"""
        amount_in = sum(_.amount for _ in self.removals())
        amount_out = sum(_.amount for _ in self.additions())
        return int(amount_in - amount_out)

    def coin_spends(self) -> list[CoinSpend]:
        return self._bundle.coin_spends

    def aggregated_signature(self) -> G2Element:
        return self._bundle.aggregated_signature

    # This method does not get every coin that is being offered, only the `settlement_payment` children
    # It's also a little heuristic, but it should get most things
    def _get_offered_coins(self) -> dict[Optional[bytes32], list[Coin]]:
        offered_coins: dict[Optional[bytes32], list[Coin]] = {}

        for parent_spend in self._bundle.coin_spends:
            coins_for_this_spend: list[Coin] = []

            parent_puzzle: UncurriedPuzzle = uncurry_puzzle(parent_spend.puzzle_reveal)
            parent_solution = Program.from_serialized(parent_spend.solution)
            additions: list[Coin] = self._additions[parent_spend.coin]

            puzzle_driver = match_puzzle(parent_puzzle)
            if puzzle_driver is not None:
                asset_id = create_asset_id(puzzle_driver)
                inner_puzzle: Optional[Program] = get_inner_puzzle(puzzle_driver, parent_puzzle, parent_solution)
                inner_solution: Optional[Program] = get_inner_solution(puzzle_driver, parent_solution)
                assert inner_puzzle is not None and inner_solution is not None

                # We're going to look at the conditions created by the inner puzzle
                conditions: Program = inner_puzzle.run(inner_solution)
                expected_num_matches: int = 0
                offered_amounts: list[int] = []
                for condition in conditions.as_iter():
                    if condition.first() == 51 and condition.rest().first() == OFFER_MOD_HASH:
                        expected_num_matches += 1
                        offered_amounts.append(condition.rest().rest().first().as_int())

                # Start by filtering additions that match the amount
                matching_spend_additions = [a for a in additions if a.amount in offered_amounts]

                if len(matching_spend_additions) == expected_num_matches:
                    coins_for_this_spend.extend(matching_spend_additions)
                # We didn't quite get there so now lets narrow it down by puzzle hash
                else:
                    # If we narrowed down too much, we can't trust the amounts so start over with all additions
                    if len(matching_spend_additions) < expected_num_matches:
                        matching_spend_additions = additions
                    matching_spend_additions = [
                        a
                        for a in matching_spend_additions
                        if a.puzzle_hash == construct_puzzle(puzzle_driver, OFFER_MOD).get_tree_hash()
                    ]
                    if len(matching_spend_additions) == expected_num_matches:
                        coins_for_this_spend.extend(matching_spend_additions)
                    else:
                        raise ValueError("Could not properly guess offered coins from parent spend")
            else:
                # It's much easier if the asset is bare XCH
                asset_id = None
                coins_for_this_spend.extend([a for a in additions if a.puzzle_hash == OFFER_MOD_HASH])

            # We only care about unspent coins
            coins_for_this_spend = [c for c in coins_for_this_spend if c not in self._bundle.removals()]

            if coins_for_this_spend != []:
                offered_coins.setdefault(asset_id, [])
                offered_coins[asset_id].extend(coins_for_this_spend)
        return offered_coins

    def get_offered_coins(self) -> dict[Optional[bytes32], list[Coin]]:
        try:
            if self._offered_coins is not None:
                return self._offered_coins
        except AttributeError:
            object.__setattr__(self, "_offered_coins", self._get_offered_coins())
        return self._offered_coins

    def get_offered_amounts(self) -> dict[Optional[bytes32], int]:
        offered_coins: dict[Optional[bytes32], list[Coin]] = self.get_offered_coins()
        offered_amounts: dict[Optional[bytes32], int] = {}
        for asset_id, coins in offered_coins.items():
            offered_amounts[asset_id] = uint64(sum(c.amount for c in coins))
        return offered_amounts

    def get_requested_payments(self) -> dict[Optional[bytes32], list[NotarizedPayment]]:
        return self.requested_payments

    def get_requested_amounts(self) -> dict[Optional[bytes32], int]:
        requested_amounts: dict[Optional[bytes32], int] = {}
        for asset_id, coins in self.get_requested_payments().items():
            requested_amounts[asset_id] = uint64(sum(c.amount for c in coins))
        return requested_amounts

    def arbitrage(self) -> dict[Optional[bytes32], int]:
        """
        Returns a dictionary of the type of each asset and amount that is involved in the trade
        With the amount being how much their offered amount within the offer
        exceeds/falls short of their requested amount.
        """
        offered_amounts: dict[Optional[bytes32], int] = self.get_offered_amounts()
        requested_amounts: dict[Optional[bytes32], int] = self.get_requested_amounts()

        arbitrage_dict: dict[Optional[bytes32], int] = {}
        for asset_id in [*requested_amounts.keys(), *offered_amounts.keys()]:
            arbitrage_dict[asset_id] = offered_amounts.get(asset_id, 0) - requested_amounts.get(asset_id, 0)

        return arbitrage_dict

    # This is a method mostly for the UI that creates a JSON summary of the offer
    def summary(self) -> tuple[dict[str, int], dict[str, int], dict[str, dict[str, Any]], ConditionValidTimes]:
        offered_amounts: dict[Optional[bytes32], int] = self.get_offered_amounts()
        requested_amounts: dict[Optional[bytes32], int] = self.get_requested_amounts()

        def keys_to_strings(dic: dict[Optional[bytes32], Any]) -> dict[str, Any]:
            new_dic: dict[str, Any] = {}
            for key, val in dic.items():
                if key is None:
                    new_dic["xch"] = val
                else:
                    new_dic[key.hex()] = val
            return new_dic

        driver_dict: dict[str, Any] = {}
        for key, value in self.driver_dict.items():
            driver_dict[key.hex()] = value.info

        return (
            keys_to_strings(offered_amounts),
            keys_to_strings(requested_amounts),
            driver_dict,
            self.absolute_valid_times_ban_relatives(),
        )

    # Also mostly for the UI, returns a dictionary of assets and how much of them is pended for this offer
    # This method is also imperfect for sufficiently complex spends
    def get_pending_amounts(self) -> dict[str, int]:
        all_additions: list[Coin] = self.additions()
        all_removals: list[Coin] = self.removals()
        non_ephemeral_removals: list[Coin] = list(filter(lambda c: c not in all_additions, all_removals))

        pending_dict: dict[str, int] = {}
        # First we add up the amounts of all coins that share an ancestor with the offered coins (i.e. a primary coin)
        for asset_id, coins in self.get_offered_coins().items():
            name = "xch" if asset_id is None else asset_id.hex()
            pending_dict[name] = 0
            for coin in coins:
                root_removal: Coin = self.get_root_removal(coin)

                for addition in filter(lambda c: c.parent_coin_info == root_removal.name(), all_additions):
                    pending_dict[name] += addition.amount

        # Then we gather anything else as unknown
        sum_of_additions_so_far: int = sum(pending_dict.values())
        unknown: int = sum(c.amount for c in non_ephemeral_removals) - sum_of_additions_so_far
        if unknown > 0:
            pending_dict["unknown"] = unknown

        return pending_dict

    # This method returns all of the coins that are being used in the offer (without which it would be invalid)
    def get_involved_coins(self) -> list[Coin]:
        additions = self.additions()
        return list(filter(lambda c: c not in additions, self.removals()))

    # This returns the non-ephemeral removal that is an ancestor of the specified coin
    # This should maybe move to the SpendBundle object at some point
    def get_root_removal(self, coin: Coin) -> Coin:
        all_removals: set[Coin] = set(self.removals())
        all_removal_ids: set[bytes32] = {c.name() for c in all_removals}
        non_ephemeral_removals: set[Coin] = {
            c for c in all_removals if c.parent_coin_info not in {r.name() for r in all_removals}
        }
        if coin.name() not in all_removal_ids and coin.parent_coin_info not in all_removal_ids:
            raise ValueError("The specified coin is not a coin in this bundle")

        while coin not in non_ephemeral_removals:
            coin = next(c for c in all_removals if c.name() == coin.parent_coin_info)

        return coin

    # This will only return coins that are ancestors of settlement payments
    def get_primary_coins(self) -> list[Coin]:
        primary_coins: set[Coin] = set()
        for _, coins in self.get_offered_coins().items():
            for coin in coins:
                primary_coins.add(self.get_root_removal(coin))
        return list(primary_coins)

    # This returns the minimum coins that when spent will invalidate the rest of the bundle
    def get_cancellation_coins(self) -> list[Coin]:
        # First, we're going to gather:
        dependencies: dict[bytes32, list[bytes32]] = {}  # all of the hashes that each coin depends on
        announcements: dict[bytes32, list[bytes32]] = {}  # all of the hashes of the announcement that each coin makes
        coin_names: list[bytes32] = []  # The names of all the coins
        additions = self.additions()
        for spend in [cs for cs in self._bundle.coin_spends if cs.coin not in additions]:
            name = bytes32(spend.coin.name())
            coin_names.append(name)
            dependencies[name] = []
            announcements[name] = []
            conditions: Program = run_with_cost(spend.puzzle_reveal, INFINITE_COST, spend.solution)[1]
            for condition in conditions.as_iter():
                if condition.first() == 60:  # create coin announcement
                    announcements[name].append(
                        AssertCoinAnnouncement(asserted_id=name, asserted_msg=condition.at("rf").as_python()).msg_calc
                    )
                elif condition.first() == 61:  # assert coin announcement
                    dependencies[name].append(bytes32(condition.at("rf").as_python()))

        # We now enter a loop that is attempting to express the following logic:
        # "If I am depending on another coin in the same bundle, you may as well cancel that coin instead of me"
        # By the end of the loop, we should have filtered down the list of coin_names to include only those that will
        # cancel everything else
        while True:
            removed = detect_dependent_coin(coin_names, dependencies, announcements)
            if removed is None:
                break
            removed_coin, provider = removed
            removed_announcements: list[bytes32] = announcements[removed_coin]
            remove_these_keys: list[bytes32] = [removed_coin]
            while True:
                for coin, deps in dependencies.items():
                    if set(deps) & set(removed_announcements) and coin != provider:
                        remove_these_keys.append(coin)
                removed_announcements = []
                for coin in remove_these_keys:
                    dependencies.pop(coin)
                    removed_announcements.extend(announcements.pop(coin))
                coin_names = [n for n in coin_names if n not in remove_these_keys]
                if removed_announcements == []:
                    break
                else:
                    remove_these_keys = []

        return [cs.coin for cs in self._bundle.coin_spends if cs.coin.name() in coin_names]

    @classmethod
    def aggregate(cls, offers: list[Offer]) -> Offer:
        total_requested_payments: dict[Optional[bytes32], list[NotarizedPayment]] = {}
        total_bundle = WalletSpendBundle([], G2Element())
        total_driver_dict: dict[bytes32, PuzzleInfo] = {}
        for offer in offers:
            # First check for any overlap in inputs
            total_inputs: set[Coin] = {cs.coin for cs in total_bundle.coin_spends}
            offer_inputs: set[Coin] = {cs.coin for cs in offer._bundle.coin_spends}
            if total_inputs & offer_inputs:
                raise ValueError("The aggregated offers overlap inputs")

            # Next, do the aggregation
            for asset_id, payments in offer.requested_payments.items():
                if asset_id in total_requested_payments:
                    total_requested_payments[asset_id].extend(payments)
                else:
                    total_requested_payments[asset_id] = payments

            for key, value in offer.driver_dict.items():
                if key in total_driver_dict and total_driver_dict[key] != value:
                    raise ValueError(f"The offers to aggregate disagree on the drivers for {key.hex()}")

            total_bundle = WalletSpendBundle.aggregate([total_bundle, offer._bundle])
            total_driver_dict.update(offer.driver_dict)

        return cls(total_requested_payments, total_bundle, total_driver_dict)

    # Validity is defined by having enough funds within the offer to satisfy both sides
    def is_valid(self) -> bool:
        return all([value >= 0 for value in self.arbitrage().values()])

    # A "valid" spend means that this bundle can be pushed to the network and will succeed
    # This differs from the `to_spend_bundle` method which deliberately creates an invalid SpendBundle
    def to_valid_spend(self, arbitrage_ph: Optional[bytes32] = None, solver: Solver = Solver({})) -> WalletSpendBundle:
        if not self.is_valid():
            raise ValueError("Offer is currently incomplete")

        completion_spends: list[CoinSpend] = []
        all_offered_coins: dict[Optional[bytes32], list[Coin]] = self.get_offered_coins()
        total_arbitrage_amount: dict[Optional[bytes32], int] = self.arbitrage()
        for asset_id, payments in self.requested_payments.items():
            offered_coins: list[Coin] = all_offered_coins[asset_id]

            # Because of CAT supply laws, we must specify a place for the leftovers to go
            arbitrage_amount: int = total_arbitrage_amount[asset_id]
            all_payments: list[NotarizedPayment] = payments.copy()
            if arbitrage_amount > 0:
                assert arbitrage_amount is not None
                assert arbitrage_ph is not None
                all_payments.append(NotarizedPayment(arbitrage_ph, uint64(arbitrage_amount)))

            # Some assets need to know about siblings so we need to collect all spends first to be able to use them
            coin_to_spend_dict: dict[Coin, CoinSpend] = {}
            coin_to_solution_dict: dict[Coin, Program] = {}
            for coin in offered_coins:
                parent_spend: CoinSpend = next(
                    filter(lambda cs: cs.coin.name() == coin.parent_coin_info, self._bundle.coin_spends)
                )
                coin_to_spend_dict[coin] = parent_spend

                inner_solutions = []
                if coin == offered_coins[0]:
                    nonces: list[bytes32] = [p.nonce for p in all_payments]
                    for nonce in list(dict.fromkeys(nonces)):  # dedup without messing with order
                        nonce_payments: list[NotarizedPayment] = list(filter(lambda p: p.nonce == nonce, all_payments))
                        inner_solutions.append((nonce, [np.as_condition_args() for np in nonce_payments]))
                coin_to_solution_dict[coin] = Program.to(inner_solutions)

            for coin in offered_coins:
                if asset_id:
                    siblings: str = "("
                    sibling_spends: str = "("
                    sibling_puzzles: str = "("
                    sibling_solutions: str = "("
                    disassembled_offer_mod: str = disassemble(OFFER_MOD)
                    for sibling_coin in offered_coins:
                        if sibling_coin != coin:
                            siblings += (
                                "0x"
                                + sibling_coin.parent_coin_info.hex()
                                + sibling_coin.puzzle_hash.hex()
                                + uint64(sibling_coin.amount).stream_to_bytes().hex()
                                + " "
                            )
                            sibling_spends += "0x" + bytes(coin_to_spend_dict[sibling_coin]).hex() + " "
                            sibling_puzzles += disassembled_offer_mod + " "
                            sibling_solutions += disassemble(coin_to_solution_dict[sibling_coin]) + " "
                    siblings += ")"
                    sibling_spends += ")"
                    sibling_puzzles += ")"
                    sibling_solutions += ")"

                    solution: Program = solve_puzzle(
                        self.driver_dict[asset_id],
                        Solver(
                            {
                                "coin": "0x"
                                + coin.parent_coin_info.hex()
                                + coin.puzzle_hash.hex()
                                + uint64(coin.amount).stream_to_bytes().hex(),
                                "parent_spend": "0x" + bytes(coin_to_spend_dict[coin]).hex(),
                                "siblings": siblings,
                                "sibling_spends": sibling_spends,
                                "sibling_puzzles": sibling_puzzles,
                                "sibling_solutions": sibling_solutions,
                                **solver.info,
                            }
                        ),
                        OFFER_MOD,
                        Program.to(coin_to_solution_dict[coin]),
                    )
                else:
                    solution = Program.to(coin_to_solution_dict[coin])

                completion_spends.append(
                    make_spend(
                        coin,
                        construct_puzzle(self.driver_dict[asset_id], OFFER_MOD) if asset_id else OFFER_MOD,
                        solution,
                    )
                )

        return WalletSpendBundle.aggregate([WalletSpendBundle(completion_spends, G2Element()), self._bundle])

    def to_spend_bundle(self) -> WalletSpendBundle:
        try:
            if self._final_spend_bundle is not None:
                return self._final_spend_bundle
        except AttributeError:
            pass
        # Before we serialize this as a SpendBundle, we need to serialize the `requested_payments` as dummy CoinSpends
        additional_coin_spends: list[CoinSpend] = []
        for asset_id, payments in self.requested_payments.items():
            puzzle_reveal: Program = construct_puzzle(self.driver_dict[asset_id], OFFER_MOD) if asset_id else OFFER_MOD
            inner_solutions = []
            nonces: list[bytes32] = [p.nonce for p in payments]
            for nonce in list(dict.fromkeys(nonces)):  # dedup without messing with order
                nonce_payments: list[NotarizedPayment] = list(filter(lambda p: p.nonce == nonce, payments))
                inner_solutions.append((nonce, [np.as_condition_args() for np in nonce_payments]))

            additional_coin_spends.append(
                make_spend(
                    Coin(
                        bytes32.zeros,
                        puzzle_reveal.get_tree_hash(),
                        uint64(0),
                    ),
                    puzzle_reveal,
                    Program.to(inner_solutions),
                )
            )

        sb = WalletSpendBundle.aggregate(
            [
                WalletSpendBundle(additional_coin_spends, G2Element()),
                self._bundle,
            ]
        )
        object.__setattr__(self, "_final_spend_bundle", sb)
        return sb

    @classmethod
    def from_spend_bundle(cls, bundle: WalletSpendBundle) -> Offer:
        # Because of the `to_spend_bundle` method, we need to parse the dummy CoinSpends as `requested_payments`
        requested_payments: dict[Optional[bytes32], list[NotarizedPayment]] = {}
        driver_dict: dict[bytes32, PuzzleInfo] = {}
        leftover_coin_spends: list[CoinSpend] = []
        for coin_spend in bundle.coin_spends:
            driver = match_puzzle(uncurry_puzzle(coin_spend.puzzle_reveal))
            if driver is not None:
                asset_id = create_asset_id(driver)
                assert asset_id is not None
                driver_dict[asset_id] = driver
            else:
                asset_id = None
            if coin_spend.coin.parent_coin_info == bytes32.zeros:
                notarized_payments: list[NotarizedPayment] = []
                for payment_group in Program.from_serialized(coin_spend.solution).as_iter():
                    nonce = bytes32(payment_group.first().as_atom())
                    payment_args_list = payment_group.rest().as_iter()
                    notarized_payments.extend(
                        [NotarizedPayment.from_condition_and_nonce(condition, nonce) for condition in payment_args_list]
                    )

                requested_payments[asset_id] = notarized_payments
            else:
                leftover_coin_spends.append(coin_spend)

        return cls(
            requested_payments, WalletSpendBundle(leftover_coin_spends, bundle.aggregated_signature), driver_dict
        )

    def name(self) -> bytes32:
        return self.to_spend_bundle().name()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Offer):
            return False  # don't attempt to compare against unrelated types
        return self.name() == other.name()

    def compress(self, version: Optional[int] = None) -> bytes:
        as_spend_bundle = self.to_spend_bundle()
        if version is None:
            mods: list[bytes] = [bytes(uncurry(s.puzzle_reveal)[0]) for s in as_spend_bundle.coin_spends]
            version = max(lowest_best_version(mods), 6)  # Clients lower than version 6 should not be able to parse
        return compress_object_with_puzzles(bytes(as_spend_bundle), version)

    @classmethod
    def from_compressed(cls, compressed_bytes: bytes) -> Offer:
        return Offer.from_bytes(decompress_object_with_puzzles(compressed_bytes))

    @classmethod
    def try_offer_decompression(cls, offer_bytes: bytes) -> Offer:
        try:
            return cls.from_compressed(offer_bytes)
        except TypeError:
            pass
        return cls.from_bytes(offer_bytes)

    def to_bech32(self, prefix: str = "offer", compression_version: Optional[int] = None) -> str:
        offer_bytes = self.compress(version=compression_version)
        encoded = bech32_encode(prefix, convertbits(list(offer_bytes), 8, 5))
        return encoded

    @classmethod
    def from_bech32(cls, offer_bech32: str) -> Offer:
        _hrpgot, data = bech32_decode(offer_bech32, max_length=len(offer_bech32))
        if data is None:
            raise ValueError("Invalid Offer")
        decoded = convertbits(list(data), 5, 8, False)
        decoded_bytes = bytes(decoded)
        return cls.try_offer_decompression(decoded_bytes)

    # Methods to make this a valid Streamable member
    # We basically hijack the SpendBundle versions for most of it
    @classmethod
    def parse(cls, f: BinaryIO) -> Offer:
        parsed_bundle = parse_rust(f, WalletSpendBundle)
        return cls.from_bytes(bytes(parsed_bundle))

    def stream(self, f: BinaryIO) -> None:
        spend_bundle_bytes = self.to_spend_bundle().to_bytes()
        f.write(spend_bundle_bytes)

    def __bytes__(self) -> bytes:
        return bytes(self.to_spend_bundle())

    @classmethod
    def from_bytes(cls, as_bytes: bytes) -> Offer:
        # Because of the __bytes__ method, we need to parse the dummy CoinSpends as `requested_payments`
        bundle = WalletSpendBundle.from_bytes(as_bytes)
        return cls.from_spend_bundle(bundle)
