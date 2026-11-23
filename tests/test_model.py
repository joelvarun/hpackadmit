"""The cost model has to agree with the reference encoder, byte for byte."""
import random

import pytest
from hpack.hpack import encode_integer

from hpackadmit.model import DEFAULT_TABLE_SIZE, Table, entry_size, prefix_len
from hpackadmit.policies import REGISTRY
from hpackadmit.trace import load, reference_bytes, replay

TRACES = load("data/response_traces.json")


def test_traces_present():
    assert len(TRACES) >= 4
    assert sum(len(t) for t in TRACES) > 1000


@pytest.mark.parametrize("name", sorted(REGISTRY))
@pytest.mark.parametrize("maxsize", [1024, DEFAULT_TABLE_SIZE])
def test_policies_match_hpack(name, maxsize):
    for t in TRACES:
        total, admit, _ = replay(t, REGISTRY[name](t, maxsize), maxsize)
        assert total == reference_bytes(t, admit, maxsize), (t.origin, name)


def test_random_policies_match_hpack():
    rng = random.Random(1234)
    for t in TRACES:
        for p in (0.1, 0.5, 0.9):
            total, admit, _ = replay(t, lambda i, f, tb: rng.random() < p)
            assert total == reference_bytes(t, admit), (t.origin, p)


def test_prefix_len_matches_hpack_integers():
    for bits in (4, 6, 7):
        for value in list(range(0, 300)) + [1000, 100000]:
            assert prefix_len(value, bits) == len(encode_integer(value, bits))


def test_oversized_entry_empties_the_table():
    table = Table(100)
    table.add(b"a", b"x" * 20)
    assert len(table.entries) == 1
    table.add(b"big", b"y" * 200)          # larger than the whole table
    assert len(table.entries) == 0 and table.size == 0


def test_fifo_eviction_keeps_the_newest_suffix():
    table = Table(200)
    sizes = []
    for i in range(6):
        name = b"n%d" % i
        table.add(name, b"v" * 10)
        sizes.append(entry_size(name, b"v" * 10))
    assert table.size <= 200
    assert table.entries[0][0] == b"n5"    # newest first
    assert sum(entry_size(n, v) for n, v in table.entries) == table.size
