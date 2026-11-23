"""Exact cost model for HPACK encoding under an admission policy.

RFC 7541 gives an encoder exactly one degree of freedom per field: whether to
insert it into the dynamic table (literal with incremental indexing) or not
(literal without indexing / never indexed). Both representations are the same
length, so admission costs nothing in bytes at the time it is made, and pays
off only through later indexed references. Its price is eviction: the table is
strict FIFO, so admitting one field pushes out the oldest ones.

This module mirrors hpack 4.1.0 exactly, which is checked in tests against the
library's own output bytes.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
from hpack.table import HeaderTable

DEFAULT_TABLE_SIZE = 4096
STATIC_LEN = HeaderTable.STATIC_TABLE_LENGTH  # 61
_HUFF = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)

# (name, value) -> static index, and name -> lowest static index for that name.
STATIC_PAIRS = {}
STATIC_NAMES = {}
for _i, (_n, _v) in enumerate(HeaderTable.STATIC_TABLE, start=1):
    STATIC_PAIRS[(_n, _v)] = _i
    STATIC_NAMES.setdefault(_n, _i)


def entry_size(name: bytes, value: bytes) -> int:
    """RFC 7541 section 4.1 accounting: 32 bytes of assumed overhead."""
    return len(name) + len(value) + 32


def prefix_len(value: int, bits: int) -> int:
    """Bytes used by an integer encoded with an N-bit prefix (section 5.1)."""
    limit = (1 << bits) - 1
    if value < limit:
        return 1
    value -= limit
    out = 2
    while value >= 128:
        value //= 128
        out += 1
    return out


def huff_len(data: bytes) -> int:
    """Length of the Huffman-coded octet string, as hpack emits it."""
    return len(_HUFF.encode(data))


def string_len(data: bytes) -> int:
    n = huff_len(data)
    return prefix_len(n, 7) + n

@dataclass(frozen=True)
class FieldCost:
    """Byte cost of one field under each representation hpack can choose.

    RFC 7541 is not symmetric about the admission decision. Literal with
    incremental indexing carries a 6 bit index prefix (section 6.2.1) while
    literal without indexing and never indexed carry only 4 bits (6.2.2,
    6.2.3). So declining to admit a field costs one extra byte whenever its
    name index is 15 or more, which is true of most of the static table. An
    encoder therefore pays a small toll for every field it holds out of the
    table, and that toll is part of the optimisation, not an afterthought.
    """
    indexed: int         # perfect match
    name_admit: int      # literal with indexed name, admitted (6 bit prefix)
    name_decline: int    # literal with indexed name, declined (4 bit prefix)
    literal: int         # literal with a fresh name, either way


def field_costs(name: bytes, value: bytes, name_index: int) -> FieldCost:
    body = string_len(value)
    return FieldCost(indexed=prefix_len(name_index, 7),
                     name_admit=prefix_len(name_index, 6) + body,
                     name_decline=prefix_len(name_index, 4) + body,
                     literal=1 + string_len(name) + body)


def encoded_len(name: bytes, value: bytes, index, perfect: bool,
                admitted: bool) -> int:
    """Bytes hpack emits for one field, given the table lookup and decision."""
    if perfect:
        return prefix_len(index, 7)
    body = string_len(value)
    if index is not None:
        bits = 6 if admitted else 4
        return prefix_len(index, bits) + body
    return 1 + string_len(name) + body


class Table:
    """The dynamic table half of hpack's HeaderTable, with FIFO eviction."""

    def __init__(self, maxsize: int = DEFAULT_TABLE_SIZE):
        self.maxsize = maxsize
        self.entries: deque = deque()   # newest first
        self.size = 0

    def search(self, name: bytes, value: bytes):
        """Return (index, perfect) using hpack's static-table-first order."""
        static = STATIC_PAIRS.get((name, value))
        if static is not None:
            return static, True
        partial = STATIC_NAMES.get(name)
        for pos, (n, v) in enumerate(self.entries):
            if n == name:
                if v == value:
                    return pos + STATIC_LEN + 1, True
                if partial is None:
                    partial = pos + STATIC_LEN + 1
        return (partial, False) if partial is not None else (None, False)

    def add(self, name: bytes, value: bytes) -> None:
        size = entry_size(name, value)
        if size > self.maxsize:
            # RFC 7541 section 4.4: an oversized entry empties the table.
            self.entries.clear()
            self.size = 0
            return
        self.entries.appendleft((name, value))
        self.size += size
        while self.size > self.maxsize:
            n, v = self.entries.pop()
            self.size -= entry_size(n, v)
