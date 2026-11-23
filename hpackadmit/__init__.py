"""Dynamic table admission control for HPACK.

RFC 7541 gives an encoder one decision per header field, insert or not, and
every shipped encoder makes it with a fixed rule. This package measures what
that costs, finds the best decision sequence a connection admits, and provides
an online policy that captures most of it.

    from hpackadmit.wire import PolicyEncoder
    enc = PolicyEncoder()
    wire = enc.encode([(b":status", b"200"), (b"etag", b'W/"7a3"')])
"""
from .model import DEFAULT_TABLE_SIZE, Table, entry_size
from .policies import REGISTRY, always, never, nghttp2, second_sight
from .trace import load, make_field, reference_bytes, replay, replay_vector
from .wire import PolicyEncoder

__version__ = "1.0.0"

__all__ = ["DEFAULT_TABLE_SIZE", "PolicyEncoder", "REGISTRY", "Table",
           "always", "entry_size", "load", "make_field", "never", "nghttp2",
           "reference_bytes", "replay", "replay_vector", "second_sight"]
