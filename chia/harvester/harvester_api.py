from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Optional, cast

from chia_rs import AugSchemeMPL, G1Element, G2Element, PlotSize, ProofOfSpace
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint8, uint32, uint64

from chia.consensus.pot_iterations import (
    calculate_iterations_quality,
    calculate_sp_interval_iters,
)
from chia.harvester.harvester import Harvester
from chia.plotting.util import PlotInfo, parse_plot_info
from chia.protocols import harvester_protocol
from chia.protocols.farmer_protocol import FarmingInfo
from chia.protocols.harvester_protocol import Plot, PlotSyncResponse
from chia.protocols.outbound_message import Message, make_msg
from chia.protocols.protocol_message_types import ProtocolMessageTypes
from chia.server.api_protocol import ApiMetadata
from chia.server.ws_connection import WSChiaConnection
from chia.types.blockchain_format.proof_of_space import (
    calculate_pos_challenge,
    calculate_prefix_bits,
    generate_plot_public_key,
    passes_plot_filter,
)
from chia.wallet.derive_keys import master_sk_to_local_sk


class HarvesterAPI:
    if TYPE_CHECKING:
        from chia.server.api_protocol import ApiProtocol

        _protocol_check: ClassVar[ApiProtocol] = cast("HarvesterAPI", None)

    log: logging.Logger
    harvester: Harvester
    metadata: ClassVar[ApiMetadata] = ApiMetadata()

    def __init__(self, harvester: Harvester):
        self.log = logging.getLogger(__name__)
        self.harvester = harvester

    def ready(self) -> bool:
        return True

    @metadata.request(peer_required=True)
    async def harvester_handshake(
        self, harvester_handshake: harvester_protocol.HarvesterHandshake, peer: WSChiaConnection
    ) -> None:
        """
        Handshake between the harvester and farmer. The harvester receives the pool public keys,
        as well as the farmer pks, which must be put into the plots, before the plotting process begins.
        We cannot use any plots which have different keys in them.
        """
        self.harvester.plot_manager.set_public_keys(
            harvester_handshake.farmer_public_keys, harvester_handshake.pool_public_keys
        )
        self.harvester.plot_sync_sender.set_connection(peer)
        await self.harvester.plot_sync_sender.start()
        self.harvester.plot_manager.start_refreshing()

    @metadata.request(peer_required=True)
    async def new_signage_point_harvester(
        self, new_challenge: harvester_protocol.NewSignagePointHarvester, peer: WSChiaConnection
    ) -> None:
        """
        The harvester receives a new signage point from the farmer, this happens at the start of each slot.
        The harvester does a few things:
        1. The harvester applies the plot filter for each of the plots, to select the proportion which are eligible
        for this signage point and challenge.
        2. The harvester gets the qualities for each plot. This is approximately 7 reads per plot which qualifies.
        Note that each plot may have 0, 1, 2, etc qualities for that challenge: but on average it will have 1.
        3. Checks the required_iters for each quality and the given signage point, to see which are eligible for
        inclusion (required_iters < sp_interval_iters).
        4. Looks up the full proof of space in the plot for each quality, approximately 64 reads per quality
        5. Returns the proof of space to the farmer
        """
        if not self.harvester.plot_manager.public_keys_available():
            # This means that we have not received the handshake yet
            self.harvester.log.debug("new_signage_point_harvester received with no keys available")
            return None

        self.harvester.log.debug(
            f"new_signage_point_harvester lookup: challenge_hash: {new_challenge.challenge_hash}, "
            f"sp_hash: {new_challenge.sp_hash}, signage_point_index: {new_challenge.signage_point_index}"
        )

        start = time.monotonic()
        assert len(new_challenge.challenge_hash) == 32

        loop = asyncio.get_running_loop()

        def blocking_lookup(filename: Path, plot_info: PlotInfo) -> list[tuple[bytes32, ProofOfSpace]]:
            # Uses the Prover object to lookup qualities. This is a blocking call,
            # so it should be run in a thread pool.
            try:
                plot_id = plot_info.prover.get_id()
                sp_challenge_hash = calculate_pos_challenge(
                    plot_id,
                    new_challenge.challenge_hash,
                    new_challenge.sp_hash,
                )
                try:
                    quality_strings = plot_info.prover.get_qualities_for_challenge(sp_challenge_hash)
                except RuntimeError as e:
                    if str(e) == "Timeout waiting for context queue.":
                        self.harvester.log.warning(
                            f"No decompressor available. Cancelling qualities retrieving for {filename}"
                        )
                        self.harvester.log.warning(
                            f"File: {filename} Plot ID: {plot_id.hex()}, challenge: {sp_challenge_hash}, "
                            f"plot_info: {plot_info}"
                        )
                    else:
                        self.harvester.log.error(f"Exception fetching qualities for {filename}. {e}")
                        self.harvester.log.error(
                            f"File: {filename} Plot ID: {plot_id.hex()}, challenge: {sp_challenge_hash}, "
                            f"plot_info: {plot_info}"
                        )
                    return []
                except Exception as e:
                    self.harvester.log.error(f"Error using prover object {e}")
                    self.harvester.log.error(
                        f"File: {filename} Plot ID: {plot_id.hex()}, "
                        f"challenge: {sp_challenge_hash}, plot_info: {plot_info}"
                    )
                    return []

                responses: list[tuple[bytes32, ProofOfSpace]] = []
                if quality_strings is not None:
                    difficulty = new_challenge.difficulty
                    sub_slot_iters = new_challenge.sub_slot_iters
                    if plot_info.pool_contract_puzzle_hash is not None:
                        # If we are pooling, override the difficulty and sub slot iters with the pool threshold info.
                        # This will mean more proofs actually get found, but they are only submitted to the pool,
                        # not the blockchain
                        for pool_difficulty in new_challenge.pool_difficulties:
                            if pool_difficulty.pool_contract_puzzle_hash == plot_info.pool_contract_puzzle_hash:
                                difficulty = pool_difficulty.difficulty
                                sub_slot_iters = pool_difficulty.sub_slot_iters

                    # Found proofs of space (on average 1 is expected per plot)
                    for index, quality_str in enumerate(quality_strings):
                        # TODO: todo_v2_plots
                        required_iters: uint64 = calculate_iterations_quality(
                            self.harvester.constants,
                            quality_str,
                            PlotSize.make_v1(plot_info.prover.get_size()),
                            difficulty,
                            new_challenge.sp_hash,
                            sub_slot_iters,
                            new_challenge.last_tx_height,
                        )
                        sp_interval_iters = calculate_sp_interval_iters(self.harvester.constants, sub_slot_iters)
                        if required_iters < sp_interval_iters:
                            # Found a very good proof of space! will fetch the whole proof from disk,
                            # then send to farmer
                            try:
                                proof_xs = plot_info.prover.get_full_proof(
                                    sp_challenge_hash, index, self.harvester.parallel_read
                                )
                            except RuntimeError as e:
                                if str(e) == "GRResult_NoProof received":
                                    self.harvester.log.info(
                                        f"Proof dropped due to line point compression for {filename}"
                                    )
                                    self.harvester.log.info(
                                        f"File: {filename} Plot ID: {plot_id.hex()}, challenge: {sp_challenge_hash}, "
                                        f"plot_info: {plot_info}"
                                    )
                                elif str(e) == "Timeout waiting for context queue.":
                                    self.harvester.log.warning(
                                        f"No decompressor available. Cancelling full proof retrieving for {filename}"
                                    )
                                    self.harvester.log.warning(
                                        f"File: {filename} Plot ID: {plot_id.hex()}, challenge: {sp_challenge_hash}, "
                                        f"plot_info: {plot_info}"
                                    )
                                else:
                                    self.harvester.log.error(f"Exception fetching full proof for {filename}. {e}")
                                    self.harvester.log.error(
                                        f"File: {filename} Plot ID: {plot_id.hex()}, challenge: {sp_challenge_hash}, "
                                        f"plot_info: {plot_info}"
                                    )
                                continue
                            except Exception as e:
                                self.harvester.log.error(f"Exception fetching full proof for {filename}. {e}")
                                self.harvester.log.error(
                                    f"File: {filename} Plot ID: {plot_id.hex()}, challenge: {sp_challenge_hash}, "
                                    f"plot_info: {plot_info}"
                                )
                                continue

                            responses.append(
                                (
                                    quality_str,
                                    ProofOfSpace(
                                        sp_challenge_hash,
                                        plot_info.pool_public_key,
                                        plot_info.pool_contract_puzzle_hash,
                                        plot_info.plot_public_key,
                                        uint8(plot_info.prover.get_size()),
                                        proof_xs,
                                    ),
                                )
                            )
                return responses
            except Exception as e:
                self.harvester.log.error(f"Unknown error: {e}")
                return []

        async def lookup_challenge(
            filename: Path, plot_info: PlotInfo
        ) -> tuple[Path, list[harvester_protocol.NewProofOfSpace]]:
            # Executes a ProverLookup in a thread pool, and returns responses
            all_responses: list[harvester_protocol.NewProofOfSpace] = []
            if self.harvester._shut_down:
                return filename, []
            proofs_of_space_and_q: list[tuple[bytes32, ProofOfSpace]] = await loop.run_in_executor(
                self.harvester.executor, blocking_lookup, filename, plot_info
            )
            for quality_str, proof_of_space in proofs_of_space_and_q:
                all_responses.append(
                    harvester_protocol.NewProofOfSpace(
                        new_challenge.challenge_hash,
                        new_challenge.sp_hash,
                        quality_str.hex() + str(filename.resolve()),
                        proof_of_space,
                        new_challenge.signage_point_index,
                        include_source_signature_data=False,
                        farmer_reward_address_override=None,
                        fee_info=None,
                    )
                )
            return filename, all_responses

        awaitables = []
        passed = 0
        total = 0
        with self.harvester.plot_manager:
            self.harvester.log.debug("new_signage_point_harvester lock acquired")
            for try_plot_filename, try_plot_info in self.harvester.plot_manager.plots.items():
                # Passes the plot filter (does not check sp filter yet though, since we have not reached sp)
                # This is being executed at the beginning of the slot
                total += 1

                # TODO: todo_v2_plots support v2 plots in PlotManager
                filter_prefix_bits = uint8(
                    calculate_prefix_bits(
                        self.harvester.constants,
                        new_challenge.peak_height,
                        PlotSize.make_v1(try_plot_info.prover.get_size()),
                    )
                )
                if passes_plot_filter(
                    filter_prefix_bits,
                    try_plot_info.prover.get_id(),
                    new_challenge.challenge_hash,
                    new_challenge.sp_hash,
                ):
                    passed += 1
                    awaitables.append(lookup_challenge(try_plot_filename, try_plot_info))
            self.harvester.log.debug(f"new_signage_point_harvester {passed} plots passed the plot filter")

        # Concurrently executes all lookups on disk, to take advantage of multiple disk parallelism
        time_taken = time.monotonic() - start
        total_proofs_found = 0
        for filename_sublist_awaitable in asyncio.as_completed(awaitables):
            filename, sublist = await filename_sublist_awaitable
            time_taken = time.monotonic() - start
            if time_taken > 8:
                self.harvester.log.warning(
                    f"Looking up qualities on {filename} took: {time_taken}. This should be below 8 seconds"
                    f" to minimize risk of losing rewards."
                )
            else:
                pass
                # self.harvester.log.info(f"Looking up qualities on {filename} took: {time_taken}")
            for response in sublist:
                total_proofs_found += 1
                msg = make_msg(ProtocolMessageTypes.new_proof_of_space, response)
                await peer.send_message(msg)

        now = uint64(time.time())

        farming_info = FarmingInfo(
            new_challenge.challenge_hash,
            new_challenge.sp_hash,
            now,
            uint32(passed),
            uint32(total_proofs_found),
            uint32(total),
            uint64(time_taken * 1_000_000),  # microseconds
        )
        pass_msg = make_msg(ProtocolMessageTypes.farming_info, farming_info)
        await peer.send_message(pass_msg)

        self.harvester.log.info(
            f"{len(awaitables)} plots were eligible for farming {new_challenge.challenge_hash.hex()[:10]}..."
            f" Found {total_proofs_found} proofs. Time: {time_taken:.5f} s. "
            f"Total {self.harvester.plot_manager.plot_count()} plots"
        )
        self.harvester.state_changed(
            "farming_info",
            {
                "challenge_hash": new_challenge.challenge_hash.hex(),
                "total_plots": self.harvester.plot_manager.plot_count(),
                "found_proofs": total_proofs_found,
                "eligible_plots": len(awaitables),
                "time": time_taken,
            },
        )

    @metadata.request(reply_types=[ProtocolMessageTypes.respond_signatures])
    async def request_signatures(self, request: harvester_protocol.RequestSignatures) -> Optional[Message]:
        """
        The farmer requests a signature on the header hash, for one of the proofs that we found.
        A signature is created on the header hash using the harvester private key. This can also
        be used for pooling.
        """
        plot_filename = Path(request.plot_identifier[64:]).resolve()
        with self.harvester.plot_manager:
            try:
                plot_info = self.harvester.plot_manager.plots[plot_filename]
            except KeyError:
                self.harvester.log.warning(f"KeyError plot {plot_filename} does not exist.")
                return None

            # Look up local_sk from plot to save locked memory
            (
                pool_public_key_or_puzzle_hash,
                farmer_public_key,
                local_master_sk,
            ) = parse_plot_info(plot_info.prover.get_memo())
            local_sk = master_sk_to_local_sk(local_master_sk)

        if isinstance(pool_public_key_or_puzzle_hash, G1Element):
            include_taproot = False
        else:
            assert isinstance(pool_public_key_or_puzzle_hash, bytes32)
            include_taproot = True

        agg_pk = generate_plot_public_key(local_sk.get_g1(), farmer_public_key, include_taproot)

        # This is only a partial signature. When combined with the farmer's half, it will
        # form a complete PrependSignature.
        message_signatures: list[tuple[bytes32, G2Element]] = []
        for message in request.messages:
            signature: G2Element = AugSchemeMPL.sign(local_sk, message, agg_pk)
            message_signatures.append((message, signature))

        response: harvester_protocol.RespondSignatures = harvester_protocol.RespondSignatures(
            request.plot_identifier,
            request.challenge_hash,
            request.sp_hash,
            local_sk.get_g1(),
            farmer_public_key,
            message_signatures,
            False,
            None,
        )

        return make_msg(ProtocolMessageTypes.respond_signatures, response)

    @metadata.request()
    async def request_plots(self, _: harvester_protocol.RequestPlots) -> Message:
        plots_response = []
        plots, failed_to_open_filenames, no_key_filenames = self.harvester.get_plots()
        for plot in plots:
            plots_response.append(
                Plot(
                    plot["filename"],
                    plot["size"],
                    plot["plot_id"],
                    plot["pool_public_key"],
                    plot["pool_contract_puzzle_hash"],
                    plot["plot_public_key"],
                    plot["file_size"],
                    plot["time_modified"],
                    plot["compression_level"],
                )
            )

        response = harvester_protocol.RespondPlots(plots_response, failed_to_open_filenames, no_key_filenames)
        return make_msg(ProtocolMessageTypes.respond_plots, response)

    @metadata.request()
    async def plot_sync_response(self, response: PlotSyncResponse) -> None:
        self.harvester.plot_sync_sender.set_response(response)
