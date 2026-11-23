"""Admission policies, online and clairvoyant.

An encoder has to decide, with no sight of the rest of the connection, whether
a field it is about to send as a literal is worth a slot in a 4096 byte FIFO
table. The policies here all have the same shape: given the field and the
current table, return True to insert it.

Two of these are shipped code. Go's net/http2 indexes every field that is not
marked sensitive and fits (`shouldIndex` in x/net/http2/hpack/encode.go), and
python-hpack does the same, its source carrying the comment that filtering out
headers which are ineffective for indexing is a future todo. nghttp2, and so
Envoy and curl and Apache httpd, goes further and keeps a hand written list of
header names out of the table. `second_sight` is the todo, and it is measured
against both.
"""
from __future__ import annotations

from collections import Counter

from .model import DEFAULT_TABLE_SIZE

GHOST_LIMIT = 512          # keys remembered but not admitted, bounded memory


def always(trace=None, maxsize=DEFAULT_TABLE_SIZE):
    """Insert everything that fits. The behaviour of every shipped encoder."""
    return lambda i, f, table: True


def never(trace=None, maxsize=DEFAULT_TABLE_SIZE):
    """Static table only, the floor you get with no dynamic state at all."""
    return lambda i, f, table: False


def size_guard(trace=None, maxsize=DEFAULT_TABLE_SIZE, share=0.125):
    """Folk rule: keep entries out if they would take too much of the table."""
    return lambda i, f, table: f.size <= share * maxsize


def second_sight(trace=None, maxsize=DEFAULT_TABLE_SIZE, room=0.5,
                 max_share=0.5):
    """Admit a value the second time it is seen, and seed each new name once.

    Three rules, all in terms of half the table:

    1. A repeated exact pair has shown that it recurs, so it will likely
       recur again and can then go out as a single byte. Admit it.
    2. The first field carrying a name that is not in the static table earns
       a slot too, because every later field with that name can then index
       the name instead of spelling it out, whatever its value. Admit it.
    3. Anything else, which on real traffic means every etag, date, request
       id and set-cookie, is admitted only while the table is less than half
       used. That is not generosity: RFC 7541 charges a byte to decline (see
       model.FieldCost), so on an uncontended table admitting is free and
       declining is not. Once the table is half full the slot is worth more
       than the byte.

    No field larger than half the table is admitted whatever its history,
    since it would evict most of the table to hold one entry. The cutoff
    matters: refusing at a quarter of the table instead costs 21 percent on
    a Cloudflare trace, because the big repeated entry there is a 2 KB
    content security policy that pays for itself many times over.

    The ghost set holds keys seen but not admitted. It is bounded, and holds
    nothing that was not already sent on the wire.
    """
    seen = set()
    ghosts = []
    names = set()

    def admit(i, f, table):
        key = (f.name, f.value)
        fresh_name = (not f.static_name) and f.name not in names
        names.add(f.name)
        repeat = key in seen
        if not repeat:
            seen.add(key)
            ghosts.append(key)
            if len(ghosts) > GHOST_LIMIT:
                seen.discard(ghosts.pop(0))
        if f.size > max_share * table.maxsize:
            return False
        if repeat or fresh_name:
            return True
        return table.size + f.size <= room * table.maxsize

    return admit


def oracle_recurrence(trace, maxsize=DEFAULT_TABLE_SIZE):
    """Clairvoyant baseline: admit only what gets used again later.

    Needs the whole connection in advance, so it is not deployable. It is here
    because it is the obvious thing to try and it is not optimal: it throws
    away the name index that an unrepeated value still provides, and on some
    traces it loses to admitting everything.
    """
    future = Counter((f.name, f.value) for f in trace.fields)

    def admit(i, f, table):
        future[(f.name, f.value)] -= 1
        return future[(f.name, f.value)] > 0

    return admit


# The names nghttp2 keeps out of the dynamic table, from
# hd_deflate_decide_indexing in lib/nghttp2_hd.c. Envoy, curl, Apache httpd
# and anything else built on nghttp2 inherits this list.
NGHTTP2_NEVER = (b":path", b"age", b"content-length", b"etag",
                 b"if-modified-since", b"if-none-match", b"location",
                 b"set-cookie")


def nghttp2(trace=None, maxsize=DEFAULT_TABLE_SIZE):
    """nghttp2's hand written admission policy, reproduced exactly.

    It is the strongest policy in production: a fixed list of header names
    that are known to carry a fresh value on every response, plus a refusal
    to spend more than three quarters of the table on one entry. Authorization
    is withheld for secrecy rather than for size, and a short cookie with it.

    The list is a good guess, and this repo exists to measure how much a good
    guess leaves behind: it cannot know that this particular server stamps
    every response with cf-ray, or x-github-request-id, or server-timing.
    """
    blocked = frozenset(NGHTTP2_NEVER)

    def admit(i, f, table):
        if f.name in blocked or f.name == b"authorization":
            return False
        if f.name == b"cookie" and len(f.value) < 20:
            return False
        return f.size <= table.maxsize * 3 // 4

    return admit


REGISTRY = {
    "never": never,
    "always": always,
    "size_guard": size_guard,
    "nghttp2": nghttp2,
    "oracle_recurrence": oracle_recurrence,
    "second_sight": second_sight,
}
