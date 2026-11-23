"""Show what admission control does to one real connection.

    python demo.py
    python demo.py --origin www.cloudflare.com --exact

Prints the per policy byte count for each captured connection, then opens up
the worst offender: which header fields the deployed policy spends the table
on, and what holding them out is worth.
"""
import argparse
from collections import defaultdict

from hpackadmit.model import DEFAULT_TABLE_SIZE
from hpackadmit.policies import REGISTRY
from hpackadmit.trace import load, reference_bytes, replay


def show_table(traces, maxsize):
    names = ["never", "always", "second_sight"]
    print("%-26s %7s %7s %10s %10s %10s %7s" %
          ("origin", "blocks", "fields", "no table", "always", "admit", "win"))
    for t in traces:
        row = {}
        for n in names:
            total, admit, _ = replay(t, REGISTRY[n](t, maxsize), maxsize)
            assert total == reference_bytes(t, admit, maxsize), "encoder drift"
            row[n] = total
        print("%-26s %7d %7d %10d %10d %10d %6.1f%%" %
              (t.origin[:26], t.block_count, len(t), row["never"],
               row["always"], row["second_sight"],
               100 * (row["always"] - row["second_sight"]) / row["always"]))
    agg = {n: 0 for n in names}
    for t in traces:
        for n in names:
            agg[n] += replay(t, REGISTRY[n](t, maxsize), maxsize)[0]
    print("%-26s %7s %7s %10d %10d %10d %6.1f%%" %
          ("all origins", "", "", agg["never"], agg["always"],
           agg["second_sight"],
           100 * (agg["always"] - agg["second_sight"]) / agg["always"]))


def explain(trace, maxsize):
    """Where the deployed policy spends the table, and what it costs."""
    wasted = defaultdict(lambda: [0, 0])
    seen = set()
    for f in trace.fields:
        key = (f.name, f.value)
        if key in seen:
            continue
        seen.add(key)
        wasted[f.name][0] += 1
        wasted[f.name][1] += f.size
    print("\n%s: %d fields over %d blocks, %d bytes of entries through a %d "
          "byte table" % (trace.origin, len(trace), trace.block_count,
                          trace.entry_bytes, maxsize))
    print("\nfields admitting everything inserts once per distinct value:")
    print("  %-34s %7s %9s" % ("header name", "values", "bytes"))
    ranked = sorted(wasted.items(), key=lambda kv: -kv[1][1])[:10]
    for name, (count, size) in ranked:
        print("  %-34s %7d %9d" % (name.decode()[:34], count, size))
    turns = trace.entry_bytes / maxsize
    print("\nthe table turns over %.1f times, so a value inserted early is "
          "gone\nlong before its next use" % turns)

    for policy in ("always", "second_sight"):
        total, admit, stats = replay(trace, REGISTRY[policy](trace, maxsize),
                                     maxsize)
        print("  %-13s %7d bytes  %4d admitted  %4d indexed  %4d literal"
              % (policy, total, sum(admit), stats["hits"], stats["literals"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default="data/response_traces.json")
    ap.add_argument("--origin", default=None)
    ap.add_argument("--table-size", type=int, default=DEFAULT_TABLE_SIZE)
    ap.add_argument("--exact", action="store_true",
                    help="also solve the admission program (slow)")
    args = ap.parse_args()

    traces = load(args.traces)
    show_table(traces, args.table_size)

    if args.origin:
        picked = [t for t in traces if t.origin == args.origin]
        if not picked:
            raise SystemExit("no trace for %s" % args.origin)
    else:
        picked = [max(traces, key=lambda t: t.entry_bytes)]
    explain(picked[0], args.table_size)

    if args.exact:
        from hpackadmit.exact import solve
        from hpackadmit.trace import replay_vector
        admit, floor, meta = solve(picked[0], args.table_size, time_limit=120.0)
        got = replay_vector(picked[0], admit, args.table_size)[0]
        print("\nadmission program: floor %.0f, achieved %d bytes, %s"
              % (floor, got, "certified optimal" if abs(got - floor) < 0.5
                 else "bracket %.2f percent" % (100 * (got - floor) / got)))


if __name__ == "__main__":
    main()
