"""A drop in encoder: hpack with an admission policy in front of it.

The policy only ever answers one question, so this wrapper is thin. It keeps a
shadow copy of the dynamic table in order to know, before asking, whether the
field is already indexed (in which case RFC 7541 leaves the encoder no choice
and no insertion happens), and it hands the answer to hpack as the `sensitive`
flag, whose non indexing representation is the same length as the one an
encoder would pick deliberately.

    from hpackadmit.wire import PolicyEncoder

    enc = PolicyEncoder()                      # one per connection
    wire = enc.encode([(b":status", b"200"), (b"etag", b'W/"7a3"')])

Output is byte identical to driving hpack directly with the same decisions,
which tests/test_wire.py checks on every captured trace.
"""
from __future__ import annotations

from hpack import Encoder

from .model import DEFAULT_TABLE_SIZE, Table
from .policies import second_sight
from .trace import make_field


class PolicyEncoder:
    """hpack.Encoder with an admission policy deciding what gets inserted."""

    def __init__(self, policy=None, maxsize: int = DEFAULT_TABLE_SIZE,
                 quirk: bool = True):
        self.policy = policy if policy is not None else second_sight()
        self.table = Table(maxsize)
        self.encoder = Encoder()
        self.encoder.header_table_size = maxsize
        self.quirk = quirk
        self.fields = 0
        self.admitted = 0
        self.indexed = 0

    def decide(self, name: bytes, value: bytes) -> bool:
        """Ask the policy about one field and update the shadow table."""
        field = make_field(name, value)
        _, perfect = self.table.search(field.name, field.value)
        if self.quirk and perfect and not field.value:
            perfect = False
        self.fields += 1
        if perfect:
            self.indexed += 1
            return False
        take = bool(self.policy(self.fields - 1, field, self.table))
        if take:
            self.admitted += 1
            self.table.add(field.name, field.value)
        return take

    def encode(self, fields) -> bytes:
        """Encode one header block. Pseudo headers must come first."""
        rows = []
        for name, value in fields:
            field = make_field(name, value)
            take = self.decide(field.name, field.value)
            rows.append((field.name, field.value, not take))
        return self.encoder.encode(rows)
