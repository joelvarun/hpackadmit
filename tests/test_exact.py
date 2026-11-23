"""The admission program must bound, and reach, the brute force optimum."""
import copy
import itertools

import pytest

from hpackadmit.exact import solve
from hpackadmit.trace import load, reference_bytes, replay_vector

TRACES = load("data/response_traces.json")


def brute(trace, maxsize):
    dec = [i for i, f in enumerate(trace.fields)
           if not (f.static_pair and f.value)]
    assert len(dec) <= 12, "keep the exhaustive search small"
    best = None
    for bits in itertools.product((False, True), repeat=len(dec)):
        admit = [False] * len(trace.fields)
        for k, i in enumerate(dec):
            admit[i] = bits[k]
        cost = replay_vector(trace, admit, maxsize)[0]
        if best is None or cost < best:
            best = cost
    return best


def head(trace, nfields):
    cut = copy.copy(trace)
    cut.fields = trace.fields[:nfields]
    return cut


def repeats(trace, nfields=13):
    """Few distinct keys, many occurrences: the case eviction decides."""
    counts = {}
    for f in trace.fields:
        counts[f.name] = counts.get(f.name, 0) + 1
    hot = {n for n, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:4]}
    cut = copy.copy(trace)
    cut.fields = [f for f in trace.fields if f.name in hot][:nfields]
    return cut


@pytest.mark.parametrize("maxsize", [192, 768])
def test_matches_brute_force_on_prefixes(maxsize):
    for t in TRACES:
        cut = head(t, 13)
        want = brute(cut, maxsize)
        admit, floor, _ = solve(cut, maxsize, time_limit=30.0)
        got = replay_vector(cut, admit, maxsize)[0]
        assert floor <= want + 1e-6, (t.origin, "floor above optimum")
        assert got == want, (t.origin, got, want)


@pytest.mark.parametrize("maxsize", [128, 320, 600])
def test_matches_brute_force_on_repeat_heavy_slices(maxsize):
    for t in TRACES:
        cut = repeats(t)
        want = brute(cut, maxsize)
        admit, floor, _ = solve(cut, maxsize, time_limit=60.0)
        got = replay_vector(cut, admit, maxsize)[0]
        assert floor <= want + 1e-6, (t.origin, "floor above optimum")
        assert got == want, (t.origin, got, want)


def test_solution_is_encodable_by_hpack():
    t = min(TRACES, key=len)
    admit, floor, _ = solve(t, 4096, time_limit=90.0)
    got = replay_vector(t, admit, 4096)[0]
    assert got == reference_bytes(t, admit, 4096)
    assert floor <= got + 1e-6
