"""The drop in encoder must emit exactly what the policy replay accounts for."""
from hpackadmit.policies import REGISTRY
from hpackadmit.trace import load, replay
from hpackadmit.wire import PolicyEncoder

TRACES = load("data/response_traces.json")


def blocks_of(trace):
    out = {}
    for f in trace.fields:
        out.setdefault(f.block, []).append((f.name, f.value))
    return [out[b] for b in sorted(out)]


def test_policy_encoder_matches_replay():
    for name in ("always", "never", "nghttp2", "second_sight"):
        for t in TRACES:
            want = replay(t, REGISTRY[name](t))[0]
            enc = PolicyEncoder(policy=REGISTRY[name](t))
            got = sum(len(enc.encode(b)) for b in blocks_of(t))
            assert got == want, (t.origin, name, got, want)


def test_policy_encoder_accepts_text():
    enc = PolicyEncoder()
    wire = enc.encode([(":status", "200"), ("etag", 'W/"7a3"')])
    assert isinstance(wire, bytes) and wire
    assert enc.fields == 2


def test_repeated_block_collapses():
    """A second identical block should cost far less than the first."""
    enc = PolicyEncoder()
    block = [(b":status", b"200"), (b"server", b"demo"),
             (b"cf-ray", b"a5e8a7e8aa7657c8-BLR")]
    first = len(enc.encode(block))
    enc.encode(block)                     # second sight admits here
    third = len(enc.encode(block))
    assert third < first
