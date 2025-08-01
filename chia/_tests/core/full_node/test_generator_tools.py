from __future__ import annotations

import pytest
from chia_rs import Program as SerializedProgram
from chia_rs import (
    SpendBundleConditions,
    SpendConditions,
    get_spends_for_trusted_block,
    get_spends_for_trusted_block_with_conditions,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32, uint64

from chia.consensus.generator_tools import tx_removals_and_additions
from chia.simulator.block_tools import test_constants
from chia.types.blockchain_format.coin import Coin
from chia.types.generator_types import BlockGenerator
from chia.util.hash import std_hash

coin_ids = [std_hash(i.to_bytes(4, "big")) for i in range(10)]
parent_ids = [std_hash(i.to_bytes(4, "big")) for i in range(10)]
phs = [std_hash(i.to_bytes(4, "big")) for i in range(10)]
spends: list[SpendConditions] = [
    SpendConditions(
        coin_ids[0],
        parent_ids[0],
        phs[0],
        123,
        None,
        uint64(5),
        None,
        None,
        None,
        None,
        [
            (phs[2], uint64(123), b""),
            (phs[3], uint64(0), b"1" * 300),
            (phs[4], uint64(0), b"1" * 300),
        ],
        [],
        [],
        [],
        [],
        [],
        [],
        [],
        0,
        execution_cost=0,
        condition_cost=0,
    ),
    SpendConditions(
        coin_ids[1],
        parent_ids[1],
        phs[0],
        123,
        None,
        uint64(2),
        None,
        None,
        None,
        None,
        [
            (phs[5], uint64(123), b""),
            (phs[6], uint64(0), b"1" * 300),
            (phs[7], uint64(0), b"1" * 300),
        ],
        [],
        [],
        [],
        [],
        [],
        [],
        [],
        0,
        execution_cost=0,
        condition_cost=0,
    ),
]


def test_tx_removals_and_additions() -> None:
    conditions = SpendBundleConditions(
        spends, uint64(0), uint32(0), uint64(0), None, None, [], uint64(0), 0, 0, False, 0, 0
    )
    expected_rems = [coin_ids[0], coin_ids[1]]
    expected_additions = []
    for spend in spends:
        for puzzle_hash, am, _ in spend.create_coin:
            expected_additions.append(Coin(bytes32(spend.coin_id), bytes32(puzzle_hash), uint64(am)))
    rems, adds = tx_removals_and_additions(conditions)
    assert rems == expected_rems
    assert adds == expected_additions


def test_empty_conditions() -> None:
    assert tx_removals_and_additions(None) == ([], [])


# this is a malicious generator which should fail
TEST_GENERATOR = BlockGenerator(
    SerializedProgram.fromhex(
        "ff02ffff01ff02ffff01ff04ffff04ffff04ffff01a00101010101010101010101010101010101010101010101010101010101010101ffff04ffff04ffff0101ffff02ff02ffff04ff02ffff04ff05ffff04ff0bffff04ff17ff80808080808080ffff01ff7bffff80ffff018080808080ff8080ff8080ffff04ffff01ff02ffff03ff17ffff01ff04ff05ffff04ff0bffff02ff02ffff04ff02ffff04ff05ffff04ff0bffff04ffff11ff17ffff010180ff8080808080808080ff8080ff0180ff018080ffff04ffff01ff42ff24ff8568656c6c6fffa0010101010101010101010101010101010101010101010101010101010101010180ffff04ffff01ff43ff24ff8568656c6c6fffa0010101010101010101010101010101010101010101010101010101010101010180ffff04ffff01830f4240ff0180808080"
    ),
    [],
)


def test_get_spends_for_block(caplog: pytest.LogCaptureFixture) -> None:
    conditions = get_spends_for_trusted_block(
        test_constants, TEST_GENERATOR.program, TEST_GENERATOR.generator_refs, 100
    )
    assert conditions[0]["block_spends"] == []


def test_get_spends_for_block_with_conditions(caplog: pytest.LogCaptureFixture) -> None:
    conditions = get_spends_for_trusted_block_with_conditions(
        test_constants, TEST_GENERATOR.program, TEST_GENERATOR.generator_refs, 100
    )
    assert conditions == []
