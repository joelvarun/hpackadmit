"""Loading header traces and replaying them through the encoder."""
from __future__ import annotations

import json
from dataclasses import dataclass

from .model import (DEFAULT_TABLE_SIZE, STATIC_LEN, STATIC_NAMES, STATIC_PAIRS,
                    Table, encoded_len, entry_size, field_costs, prefix_len)


@dataclass
class Field:
    name: bytes
    value: bytes
    block: int
    size: int
    static_pair: bool
    static_name: bool


@dataclass
class Trace:
    origin: str
    fields: list
    block_count: int

    def __len__(self):
        return len(self.fields)

    @property
    def entry_bytes(self):
        return sum(f.size for f in self.fields)


def make_field(name, value, block=0):
    """Build one Field from raw bytes, filling in the static table flags."""
    if isinstance(name, str):
        name = name.encode("utf8")
    if isinstance(value, str):
        value = value.encode("utf8")
    return Field(name, value, block, entry_size(name, value),
                 (name, value) in STATIC_PAIRS, name in STATIC_NAMES)


def load(path):
    """Read a capture written by tools/fetch_corpus.py."""
    with open(path, encoding="utf8") as fh:
        raw = json.load(fh)
    traces = []
    for t in raw["traces"]:
        fields = []
        for bi, block in enumerate(t["blocks"]):
            for name, value in block["fields"]:
                fields.append(make_field(name, value, bi))
        traces.append(Trace(t["origin"], fields, len(t["blocks"])))
    return traces


def replay(trace, admit_fn, maxsize=DEFAULT_TABLE_SIZE, quirk=True):
    """Encode a trace, asking admit_fn about every field that misses.

    quirk reproduces one behaviour of hpack 4.1.0: Encoder.add tests the value
    returned by HeaderTable.search for truthiness, so a field with an empty
    value never takes the 1 byte indexed representation even on a perfect
    match, and gets re-inserted on every occurrence. Keeping it on makes every
    number here match the bytes the shipped library actually emits; turning it
    off gives the RFC 7541 reading.

    Returns (total_bytes, admit_vector, stats).
    """
    table = Table(maxsize)
    # Any table size other than the protocol default has to be announced once
    # with a dynamic table size update (RFC 7541 section 6.3). It is the same
    # constant for every policy, so it changes no comparison.
    total = 0 if maxsize == DEFAULT_TABLE_SIZE else prefix_len(maxsize, 5)
    admit = [False] * len(trace.fields)
    hits = names = literals = clears = 0
    peak_entries = 0
    for i, f in enumerate(trace.fields):
        index, perfect = table.search(f.name, f.value)
        if quirk and perfect and not f.value:
            perfect = False
        if perfect:
            total += encoded_len(f.name, f.value, index, True, False)
            hits += 1
            continue
        if index is None:
            literals += 1
        else:
            names += 1
        taken = bool(admit_fn(i, f, table))
        total += encoded_len(f.name, f.value, index, False, taken)
        if taken:
            admit[i] = True
            if f.size > maxsize:
                clears += 1
            table.add(f.name, f.value)
            peak_entries = max(peak_entries, len(table.entries))
    return total, admit, {"hits": hits, "name_indexed": names,
                          "literals": literals, "table_clears": clears,
                          "peak_entries": peak_entries}


def replay_vector(trace, admit, maxsize=DEFAULT_TABLE_SIZE, quirk=True):
    """Replay a fixed admission vector (used to score solver output)."""
    return replay(trace, lambda i, f, t: admit[i], maxsize, quirk)


def reference_bytes(trace, admit, maxsize=DEFAULT_TABLE_SIZE):
    """Encode with the hpack library itself, as the wire-truth check.

    A field we decline to admit is passed as sensitive, which hpack renders as
    a never-indexed literal: identical length to a literal without indexing,
    and it leaves the table alone.
    """
    from hpack import Encoder
    enc = Encoder()
    enc.header_table_size = maxsize
    blocks = {}
    for k, f in enumerate(trace.fields):
        blocks.setdefault(f.block, []).append((f.name, f.value, not admit[k]))
    return sum(len(enc.encode(blocks[bi])) for bi in sorted(blocks))


def lower_bound_costs(trace, quirk=True):
    """Optimistic per-field costs, used as MILP objective coefficients.

    Dynamic index prefixes are costed at their smallest legal width (the
    newest entry, index 62), so the MILP objective is a valid lower bound on
    what the encoder can actually emit. Static indices are exact.
    """
    out = []
    for f in trace.fields:
        if quirk and not f.value:
            c = field_costs(f.name, f.value,
                            STATIC_NAMES.get(f.name, STATIC_LEN + 1))
            out.append((c.name_admit, c.name_admit, c.name_decline, c.literal))
        elif f.static_pair:
            c = field_costs(f.name, f.value, STATIC_PAIRS[(f.name, f.value)])
            out.append((c.indexed, c.indexed, c.indexed, c.indexed))
        elif f.static_name:
            c = field_costs(f.name, f.value, STATIC_NAMES[f.name])
            best = field_costs(f.name, f.value, STATIC_LEN + 1)
            out.append((best.indexed, c.name_admit, c.name_decline, c.literal))
        else:
            c = field_costs(f.name, f.value, STATIC_LEN + 1)
            out.append((c.indexed, c.name_admit, c.name_decline, c.literal))
    return out
