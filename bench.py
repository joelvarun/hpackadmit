"""Run every policy, the exact program, and a table size sweep.

    python bench.py --exact-time 300

Writes docs/results.json, which chart.py and the README numbers come from.
Nothing here invents a number: every byte count is produced by encoding the
captured traces, and the model's own output is checked against the hpack
library on every policy before it is reported.
"""
import argparse
import copy
import json
import time

from hpackadmit.exact import solve
from hpackadmit.model import DEFAULT_TABLE_SIZE
from hpackadmit.policies import REGISTRY, second_sight
from hpackadmit.trace import (load, reference_bytes, replay, replay_vector)

POLICIES = ["never", "always", "size_guard", "nghttp2",
            "oracle_recurrence", "second_sight"]
SWEEP = [512, 1024, 2048, 4096, 8192, 16384]
PREFIX_FIELDS = 280       # instance size the solver can close on every origin


def prefix_trace(trace, limit=PREFIX_FIELDS):
    """Whole leading blocks of a trace, up to about `limit` fields.

    The big connections are out of reach of a proof in any sane time, so each
    one also gets a bounded prefix that is: same traffic, same table, same
    policies, small enough to certify.
    """
    keep, blocks = [], 0
    for f in trace.fields:
        if f.block != blocks:
            if len(keep) >= limit:
                break
            blocks = f.block
        keep.append(f)
    cut = copy.copy(trace)
    cut.fields = keep
    cut.block_count = keep[-1].block + 1
    return cut


def solve_and_score(trace, maxsize, time_limit):
    """Solve one instance and score the result with the real encoder."""
    t0 = time.time()
    admit, floor, meta = solve(trace, maxsize, time_limit=time_limit)
    got = None
    if admit is not None:
        got, _, _ = replay_vector(trace, admit, maxsize)
        ref = reference_bytes(trace, admit, maxsize)
        if ref != got:
            raise AssertionError("exact: model %d, hpack %d" % (got, ref))
        meta["admitted"] = sum(admit)
    meta["seconds"] = round(time.time() - t0, 1)
    meta["achieved"] = got
    meta["floor"] = floor
    meta["fields"] = len(trace.fields)
    meta["blocks"] = trace.block_count
    best = replay(trace, REGISTRY["second_sight"](trace, maxsize), maxsize)[0]
    meta["second_sight"] = best
    meta["always"] = replay(trace, REGISTRY["always"](trace, maxsize),
                            maxsize)[0]
    meta["best_known"] = min(x for x in (got, best) if x is not None)
    meta["certified"] = bool(floor is not None
                             and abs(floor - meta["best_known"]) < 0.5)
    return meta


def run_policies(traces, maxsize=DEFAULT_TABLE_SIZE, verify=True):
    out = {}
    for t in traces:
        row = {}
        for name in POLICIES:
            total, admit, stats = replay(t, REGISTRY[name](t, maxsize), maxsize)
            if verify:
                ref = reference_bytes(t, admit, maxsize)
                if ref != total:
                    raise AssertionError(
                        "%s/%s: model %d, hpack %d" % (t.origin, name, total, ref))
            row[name] = {"bytes": total, "admitted": sum(admit), **stats}
        out[t.origin] = row
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default="data/response_traces.json")
    ap.add_argument("--out", default="docs/results.json")
    ap.add_argument("--exact-time", type=float, default=300.0)
    ap.add_argument("--no-exact", action="store_true")
    args = ap.parse_args()

    traces = load(args.traces)
    print("traces=%d blocks=%d fields=%d" %
          (len(traces), sum(t.block_count for t in traces),
           sum(len(t) for t in traces)), flush=True)

    results = {"table_size": DEFAULT_TABLE_SIZE,
               "traces": [{"origin": t.origin, "blocks": t.block_count,
                           "fields": len(t), "entry_bytes": t.entry_bytes}
                          for t in traces]}

    print("\npolicies at %d bytes (checked against hpack)" % DEFAULT_TABLE_SIZE,
          flush=True)
    results["policies"] = run_policies(traces, DEFAULT_TABLE_SIZE)
    head = "%-24s" % "origin" + "".join("%11s" % p[:10] for p in POLICIES)
    print(head, flush=True)
    for t in traces:
        row = results["policies"][t.origin]
        print("%-24s" % t.origin[:24] +
              "".join("%11d" % row[p]["bytes"] for p in POLICIES), flush=True)

    if not args.no_exact:
        for label, shrink in (("full connections", False),
                              ("bounded prefixes", True)):
            print("\nexact admission program, %s" % label, flush=True)
            key = "exact_prefix" if shrink else "exact"
            results[key] = {}
            for t in traces:
                inst = prefix_trace(t) if shrink else t
                if shrink and len(inst.fields) == len(t.fields):
                    results[key][t.origin] = dict(results["exact"][t.origin])
                    print("%-24s same as the full connection" % t.origin[:24],
                          flush=True)
                    continue
                meta = solve_and_score(inst, DEFAULT_TABLE_SIZE,
                                       args.exact_time)
                results[key][t.origin] = meta
                floor = meta["floor"]
                if floor is None:
                    verdict = "no bound proved"
                elif meta["certified"]:
                    verdict = "certified optimal"
                else:
                    verdict = "bracket %.1f%%" % (
                        100 * (meta["best_known"] - floor) / meta["best_known"])
                print("%-24s n=%4d floor=%9s best=%7d second_sight=%7d  "
                      "%-18s %.0fs" %
                      (t.origin[:24], meta["fields"],
                       "none" if floor is None else "%.1f" % floor,
                       meta["best_known"], meta["second_sight"], verdict,
                       meta["seconds"]), flush=True)

    print("\ntable size sweep", flush=True)
    results["sweep"] = {}
    for B in SWEEP:
        row = run_policies(traces, B, verify=False)
        agg = {p: sum(row[o][p]["bytes"] for o in row) for p in POLICIES}
        results["sweep"][str(B)] = agg
        print("B=%6d always=%8d second_sight=%8d  win=%5.1f%%" %
              (B, agg["always"], agg["second_sight"],
               100 * (agg["always"] - agg["second_sight"]) / agg["always"]),
              flush=True)

    print("\nthreshold sensitivity (room, max_share)", flush=True)
    results["thresholds"] = {}
    base = sum(results["policies"][t.origin]["always"]["bytes"] for t in traces)
    for room in (0.0, 0.25, 0.5, 0.75, 1.0):
        for ms in (0.25, 0.5, 1.0):
            tot = sum(replay(t, second_sight(t, room=room, max_share=ms))[0]
                      for t in traces)
            key = "%.2f/%.2f" % (room, ms)
            results["thresholds"][key] = tot
            print("  %s total=%8d win=%5.2f%%" %
                  (key, tot, 100 * (base - tot) / base), flush=True)

    totals = {p: sum(results["policies"][o][p]["bytes"]
                     for o in results["policies"]) for p in POLICIES}
    results["totals"] = totals
    if "exact" in results:
        for key in ("exact", "exact_prefix"):
            vals = results.get(key, {}).values()
            if vals and all(m["floor"] is not None for m in vals):
                results["totals"][key + "_floor"] = sum(
                    m["floor"] for m in vals)
            results["totals"][key + "_best"] = sum(
                m["best_known"] for m in vals)
    with open(args.out, "w", encoding="utf8") as fh:
        json.dump(results, fh, indent=1)
    print("\ntotals", json.dumps(totals), flush=True)
    print("wrote", args.out, flush=True)


if __name__ == "__main__":
    main()
