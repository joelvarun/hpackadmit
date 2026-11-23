"""Render docs/before_after.png from docs/results.json.

    python bench.py --exact-time 300
    python chart.py

Every number plotted comes out of bench.py, which encodes the captured traces
with the hpack library. Nothing here computes or adjusts a result.
"""
import argparse
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#8a8982"
BEFORE = "#2a78d6"     # categorical slot 1
AFTER = "#eb6834"      # categorical slot 2
SHIPPED = "#1baf7a"    # categorical slot 3


def kb(x, _=None):
    return "%.0fk" % (x / 1000.0) if x >= 1000 else "%d" % x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="docs/results.json")
    ap.add_argument("--out", default="docs/before_after.png")
    args = ap.parse_args()
    r = json.load(open(args.results, encoding="utf8"))

    origins = [t["origin"] for t in r["traces"]]
    pol = r["policies"]
    before = [pol[o]["always"]["bytes"] for o in origins]
    shipped = [pol[o]["nghttp2"]["bytes"] for o in origins]
    after = [pol[o]["second_sight"]["bytes"] for o in origins]
    floors = [r.get("exact", {}).get(o, {}).get("floor") for o in origins]

    order = sorted(range(len(origins)), key=lambda i: before[i])
    origins = [origins[i] for i in order]
    before = [before[i] for i in order]
    shipped = [shipped[i] for i in order]
    after = [after[i] for i in order]
    floors = [floors[i] for i in order]

    fig, (ax, bx) = plt.subplots(
        1, 2, figsize=(13.4, 5.6), gridspec_kw={"width_ratios": [1.35, 1]})
    fig.patch.set_facecolor(SURFACE)

    ys = range(len(origins))
    h = 0.25
    ax.set_facecolor(SURFACE)
    ax.barh([y + h + 0.02 for y in ys], before, height=h, color=BEFORE,
            label="always index (Go net/http2, python-hpack)")
    ax.barh(list(ys), shipped, height=h, color=SHIPPED,
            label="nghttp2 name blocklist (Envoy, curl, httpd)")
    ax.barh([y - h - 0.02 for y in ys], after, height=h, color=AFTER,
            label="hpackadmit, second sight admission")
    pad = max(before) * 0.012
    for y, b, sh, a, fl in zip(ys, before, shipped, after, floors):
        ax.text(b + pad, y + h + 0.02, kb(b), va="center", fontsize=8,
                color=INK2)
        ax.text(sh + pad, y, kb(sh), va="center", fontsize=8, color=INK2)
        ax.text(a + pad, y - h - 0.02,
                "%s  (%+.0f%% vs nghttp2)" % (kb(a), -100.0 * (sh - a) / sh),
                va="center", fontsize=8, color=INK)
        if fl:
            ax.plot([fl], [y - h - 0.02], marker="|", markersize=11,
                    markeredgewidth=1.6, color=MUTED, zorder=5,
                    linestyle="none")
    ax.plot([], [], marker="|", markersize=11, markeredgewidth=1.6,
            color=MUTED, linestyle="none",
            label="certified floor, where the solver proved one")
    ax.set_yticks(list(ys))
    ax.set_yticklabels(origins, fontsize=9.5, color=INK)
    ax.set_xlabel("HPACK encoded header bytes per connection", fontsize=9.5,
                  color=INK2)
    ax.xaxis.set_major_formatter(FuncFormatter(kb))
    ax.set_xlim(0, max(before) * 1.26)
    ax.grid(axis="x", color="#e7e6e1", linewidth=0.8)
    ax.set_axisbelow(True)
    tot_b, tot_a = sum(before), sum(after)
    tot_s = sum(shipped)
    fig.suptitle("HPACK response headers on six real HTTP/2 origins: "
                 "%s to %s bytes, %.1f percent fewer than the best shipped "
                 "policy" % (kb(tot_s), kb(tot_a),
                             100.0 * (tot_s - tot_a) / tot_s),
                 fontsize=12.5, color=INK, x=0.011, ha="left", y=0.975)
    ax.set_title("Per connection, table at the 4096 byte default",
                 fontsize=10.5, color=INK2, loc="left", pad=10)
    ax.legend(loc="lower right", frameon=False, fontsize=8.5,
              labelcolor=INK2)

    sizes = sorted(int(k) for k in r["sweep"])
    sb = [r["sweep"][str(s)]["always"] for s in sizes]
    ss = [r["sweep"][str(s)]["nghttp2"] for s in sizes]
    sa = [r["sweep"][str(s)]["second_sight"] for s in sizes]
    bx.set_facecolor(SURFACE)
    bx.plot(sizes, sb, color=BEFORE, linewidth=2, marker="o", markersize=5,
            label="always index")
    bx.plot(sizes, ss, color=SHIPPED, linewidth=2, marker="o", markersize=5,
            label="nghttp2 blocklist")
    bx.plot(sizes, sa, color=AFTER, linewidth=2, marker="o", markersize=5,
            label="hpackadmit")
    bx.legend(loc="upper right", frameon=False, fontsize=9, labelcolor=INK2,
              handlelength=1.4, borderaxespad=0.2)
    span = max(sb) - min(sa)
    for s, sh, a in zip(sizes, ss, sa):
        bx.annotate("%.0f%% fewer" % (100.0 * (sh - a) / sh) if s == 4096
                    else "%.0f%%" % (100.0 * (sh - a) / sh),
                    (s, a), xytext=(0, -14), textcoords="offset points",
                    fontsize=8, color=INK2, ha="center",
                    bbox=dict(facecolor=SURFACE, edgecolor="none", pad=0.8))
    bx.set_ylim(min(sa) - span * 0.1, max(sb) + span * 0.06)
    bx.set_xscale("log", base=2)
    bx.set_xticks(sizes)
    bx.set_xticklabels([kb(s) if s >= 1000 else str(s) for s in sizes],
                       fontsize=9)
    bx.yaxis.set_major_formatter(FuncFormatter(kb))
    bx.set_xlabel("SETTINGS_HEADER_TABLE_SIZE (bytes), 4k is the default",
                  fontsize=9.5, color=INK2)
    bx.set_ylabel("total encoded header bytes, all six origins", fontsize=9.5,
                  color=INK2)
    bx.grid(color="#e7e6e1", linewidth=0.8)
    bx.set_axisbelow(True)
    bx.set_title("The gain tracks table pressure, peaking at the default",
                 fontsize=10.5, color=INK2, loc="left", pad=10)
    bx.axvline(4096, color=MUTED, linewidth=1, linestyle=(0, (4, 3)))

    for a in (ax, bx):
        for side in ("top", "right"):
            a.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            a.spines[side].set_color("#d9d8d2")
        a.tick_params(colors=INK2, labelsize=9, length=3)

    fig.tight_layout(pad=1.6, rect=(0, 0, 1, 0.945))
    fig.savefig(args.out, dpi=170, facecolor=SURFACE)
    print("wrote %s  always=%d nghttp2=%d hpackadmit=%d "
          "(%.1f%% below always, %.1f%% below nghttp2)"
          % (args.out, tot_b, tot_s, tot_a,
             100.0 * (tot_b - tot_a) / tot_b,
             100.0 * (tot_s - tot_a) / tot_s))


if __name__ == "__main__":
    main()
