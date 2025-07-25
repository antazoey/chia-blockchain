from __future__ import annotations

import random
import unittest

import pytest
from chia_rs import CoinSpend, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode

BLANK_SPEND_BUNDLE = SpendBundle(coin_spends=[], aggregated_signature=G2Element())
NULL_SIGNATURE = "0xc" + "0" * 191


class TestStructStream(unittest.TestCase):
    def test_round_trip(self):
        spend_bundle = BLANK_SPEND_BUNDLE
        json_dict = spend_bundle.to_json_dict()

        sb = SpendBundle.from_json_dict(json_dict)

        assert sb == spend_bundle


def rand_hash(rng: random.Random) -> bytes32:
    return bytes32.random(r=rng)


def create_spends(num: int) -> tuple[list[CoinSpend], list[Coin]]:
    spends: list[CoinSpend] = []
    create_coin: list[Coin] = []
    rng = random.Random()

    puzzle = Program.to(1)
    puzzle_hash = puzzle.get_tree_hash()

    for i in range(num):
        target_ph = rand_hash(rng)
        conditions = [[ConditionOpcode.CREATE_COIN, target_ph, 1]]
        coin = Coin(rand_hash(rng), puzzle_hash, uint64(1000))
        new_coin = Coin(coin.name(), target_ph, uint64(1))
        create_coin.append(new_coin)
        spends.append(make_spend(coin, puzzle, Program.to(conditions)))

    return spends, create_coin


def test_compute_additions_create_coin() -> None:
    # make a large number of CoinSpends
    spends, create_coin = create_spends(2000)
    sb = SpendBundle(spends, G2Element())
    coins = sb.additions()
    assert coins == create_coin


def test_compute_additions_create_coin_max_cost() -> None:
    # make a large number of CoinSpends
    spends, _ = create_spends(6111)
    sb = SpendBundle(spends, G2Element())
    with pytest.raises(ValueError, match="cost exceeded"):
        sb.additions()
