"""Exact admission optimum for one trace, as a mixed integer program.

The whole problem is the FIFO table. An entry admitted at field j is still
there at field i exactly when the admitted bytes in the half open range [j, i)
fit in the table, so liveness is a window sum on one monotone clock rather than
a set membership test:

    C_i = sum of s_k over admitted k < i,      live(j, i)  iff  C_i - C_j <= B

What the program carries per key is that window sum directly, capped at B + 1:

    G_i = min(B + 1, bytes admitted since the newest admitted earlier
                     occurrence of this key)

G resets to s_j when occurrence j is admitted and otherwise accumulates, which
is two linear rows selected by the admission variable, with no extra binaries
and with coefficients on the scale of the table rather than of the trace. A
field can take the indexed representation only where its key's gap still fits,
which is the single row G_i + h_i <= B + 1.

Oversized fields need no special case. RFC 7541 section 4.4 empties the table
when an entry exceeds its capacity, and the gap reproduces that for free:
advancing by more than B kills every older entry and the new one as well.

Index prefixes are costed at their narrowest legal width, which is the one
deliberate relaxation: every real admission policy maps to a feasible point of
this program whose modelled cost is no greater than the bytes the encoder
really emits. So the solver's dual bound is a floor under every encoder, and
the returned admission vector, scored by the real encoder, is a ceiling. When
the two meet, that vector is certified optimal.
"""
from __future__ import annotations

import numpy as np
from scipy.optimize import LinearConstraint, milp
from scipy.sparse import coo_matrix

from .model import DEFAULT_TABLE_SIZE, prefix_len
from .trace import lower_bound_costs


class _Vars:
    def __init__(self):
        self.lb, self.ub, self.integral, self.names = [], [], [], []

    def add(self, lo, hi, integral, name):
        self.lb.append(lo)
        self.ub.append(hi)
        self.integral.append(1 if integral else 0)
        self.names.append(name)
        return len(self.lb) - 1


class _Rows:
    """Accumulates sparse rows of the form lo <= a.x <= hi."""

    def __init__(self):
        self.r, self.c, self.v, self.lo, self.hi = [], [], [], [], []

    def add(self, terms, lo, hi):
        i = len(self.lo)
        for col, coef in terms:
            self.r.append(i)
            self.c.append(col)
            self.v.append(float(coef))
        self.lo.append(lo)
        self.hi.append(hi)

    def matrix(self, ncols):
        return coo_matrix((self.v, (self.r, self.c)),
                          shape=(len(self.lo), ncols)).tocsr()


def _chains(fields):
    """Occurrence lists per key, plus what each field could do with them."""
    n = len(fields)
    decision, can_hit, can_name = [], [False] * n, [False] * n
    pair_chain, name_chain = {}, {}
    for i, f in enumerate(fields):
        empty = not f.value
        if f.static_pair and not empty:
            continue                       # always a 1 byte static index
        decision.append(i)
        if not empty:
            key = (f.name, f.value)
            can_hit[i] = key in pair_chain
            pair_chain.setdefault(key, []).append(i)
        if not f.static_name:
            can_name[i] = f.name in name_chain
            name_chain.setdefault(f.name, []).append(i)
    return decision, can_hit, can_name, pair_chain, name_chain


def build(trace, maxsize=DEFAULT_TABLE_SIZE, quirk=True):
    """Return (vars, rows, objective, x columns, meta) for one trace."""
    fields = trace.fields
    n = len(fields)
    costs = lower_bound_costs(trace, quirk)
    B = maxsize
    CAP = B + 1                            # a gap this wide means evicted

    decision, can_hit, can_name, pair_chain, name_chain = _chains(fields)
    dec = set(decision)
    total = sum(fields[i].size for i in dec)

    V, R = _Vars(), _Rows()
    obj = {}
    # A non default table size has to be announced once on the wire.
    const = 0.0 if B == DEFAULT_TABLE_SIZE else float(prefix_len(B, 5))

    # Cumulative admitted bytes before each field, by recursion so that every
    # row stays sparse.
    c_col = [V.add(0, total, False, "C%d" % i) for i in range(n + 1)]
    R.add([(c_col[0], 1)], 0, 0)
    x_col, h_col, m_col = {}, {}, {}
    for i, f in enumerate(fields):
        if i in dec:
            x_col[i] = V.add(0, 1, True, "x%d" % i)
            R.add([(c_col[i + 1], 1), (c_col[i], -1), (x_col[i], -f.size)], 0, 0)
        else:
            R.add([(c_col[i + 1], 1), (c_col[i], -1)], 0, 0)
            const += costs[i][0]

    dead_col = {}

    def chain(occ, tag):
        """Gap variables along one key's occurrences, saturating at CAP.

        d marks the key as having no live entry. The gap can genuinely exceed
        CAP, so it has to saturate there rather than be clipped, or the
        program would simply have no feasible point for an admission pattern
        that evicts the key. Once a key is dead it stays dead until it is
        admitted again, which is what makes saturation exact.
        """
        gaps = {}
        prev_g, prev_i, prev_d = None, None, None
        for t, i in enumerate(occ):
            g = V.add(0, CAP, False, "%s%d" % (tag, i))
            if t == 0:
                R.add([(g, 1)], CAP, CAP)   # nothing admitted yet, so dead
            else:
                j = prev_i
                d = V.add(0, 1, True, "d%s%d" % (tag, i))
                # Both relaxations are switched by d, so neither constant has
                # to cover the whole trace: any window wider than the table
                # forces d on, and a dead key is all the program needs to
                # know. That keeps every coefficient near the table size
                # instead of near the sum of the connection.
                u1 = CAP + fields[j].size
                u2 = u1 + CAP
                # Admitted at j: the gap restarts there, and C_i - C_j is then
                # exactly the admitted bytes in [j, i).
                R.add([(g, 1), (c_col[i], -1), (c_col[j], 1),
                       (x_col[j], -u1), (d, u1)], -u1, None)
                # Declined at j: the earlier gap carries forward plus whatever
                # was admitted in between.
                R.add([(g, 1), (c_col[i], -1), (c_col[j], 1), (prev_g, -1),
                       (x_col[j], u2), (d, u2)], 0, None)
                # Dead means the gap saturates, which forbids the index below.
                R.add([(g, 1), (d, -CAP)], 0, None)
                # A key that was dead at j and was not admitted there is still
                # dead at i. The gap rows already imply this, but stating it
                # keeps the relaxation from buying hits with fractional d.
                if prev_d is not None:
                    R.add([(d, 1), (prev_d, -1), (x_col[j], 1)], 0, None)
                dead_col[(tag, i)] = d
                prev_d = d
            gaps[i] = g
            prev_g, prev_i = g, i
        return gaps

    pair_gap, name_gap, name_span = {}, {}, {}
    for key, occ in pair_chain.items():
        if len(occ) > 1:
            pair_gap.update(chain(occ, "gp"))
    for nm, occ in name_chain.items():
        if len(occ) > 1:
            name_gap.update(chain(occ, "gn"))
            name_span[nm] = max(fields[i].size for i in occ)

    for i in decision:
        f = fields[i]
        c_hit, c_adm, c_dec, c_lit = costs[i]
        if can_hit[i]:
            h_col[i] = V.add(0, 1, True, "h%d" % i)
            R.add([(pair_gap[i], 1), (h_col[i], 1)], None, CAP)
            R.add([(h_col[i], 1), (dead_col[("gp", i)], 1)], None, 1)
            # A perfect match is emitted as an index and inserts nothing, so
            # the request to admit is a no-op exactly where a hit is taken.
            R.add([(x_col[i], 1), (h_col[i], 1)], None, 1)
        if can_name[i]:
            m_col[i] = V.add(0, 1, True, "m%d" % i)
            R.add([(name_gap[i], 1), (m_col[i], 1)], None, CAP)
            R.add([(m_col[i], 1), (dead_col[("gn", i)], 1)], None, 1)
            if can_hit[i]:
                R.add([(h_col[i], 1), (m_col[i], 1)], None, 1)

        # Cost with no dynamic help: a static name still indexes for free,
        # anything else has to spell the name out.
        base = c_dec if f.static_name else c_lit
        const += base
        if i in h_col:
            obj[h_col[i]] = obj.get(h_col[i], 0.0) + (c_hit - base)
        if i in m_col:
            obj[m_col[i]] = obj.get(m_col[i], 0.0) + (c_dec - c_lit)
        delta = c_dec - c_adm if (f.static_name or can_name[i]) else 0
        if delta:
            # Admitting is a byte cheaper than declining: RFC 7541 gives
            # incremental indexing a 6 bit index prefix and the two non
            # indexing forms only 4 bits.
            q = V.add(0, 1, False, "q%d" % i)
            R.add([(q, 1), (x_col[i], -1)], None, 0)
            if i in h_col:
                R.add([(q, 1), (h_col[i], 1)], None, 1)
            if not f.static_name:
                # A dynamic name index is one byte only at index 62, the
                # newest entry, so nothing can have been admitted in between.
                R.add([(q, 1), (m_col[i], -1)], None, 0)
                R.add([(name_gap[i], 1), (q, CAP - name_span[f.name])],
                      None, CAP)
            obj[q] = obj.get(q, 0.0) - delta

    meta = {"decisions": len(decision), "hit_vars": len(h_col),
            "name_vars": len(m_col), "const": const,
            "n_vars": len(V.lb), "n_rows": len(R.lo),
            "n_binary": int(sum(V.integral))}
    return V, R, obj, x_col, meta


def solve(trace, maxsize=DEFAULT_TABLE_SIZE, quirk=True, time_limit=120.0,
          mip_gap=0.0):
    """Solve the admission program. Returns (admit vector, bound, meta)."""
    V, R, obj, x_col, meta = build(trace, maxsize, quirk)
    ncols = len(V.lb)
    c = np.zeros(ncols)
    for col, coef in obj.items():
        c[col] = coef
    lo = np.array([-np.inf if v is None else v for v in R.lo])
    hi = np.array([np.inf if v is None else v for v in R.hi])
    res = milp(c=c,
               constraints=LinearConstraint(R.matrix(ncols), lo, hi),
               bounds=(np.array(V.lb, dtype=float), np.array(V.ub, dtype=float)),
               integrality=np.array(V.integral),
               options={"time_limit": time_limit, "mip_rel_gap": mip_gap,
                        "presolve": True})
    admit = None
    if res.x is not None:
        admit = [False] * len(trace.fields)
        for i, col in x_col.items():
            admit[i] = bool(res.x[col] > 0.5)
    # Only a dual bound the solver actually proved is a floor. If it has none,
    # say so rather than reporting the objective constant as if it were one.
    dual = res.mip_dual_bound
    floor = None
    if dual is not None and np.isfinite(dual):
        floor = float(meta["const"] + dual)
    meta.update({"status": int(res.status), "message": str(res.message)[:90],
                 "objective": float(meta["const"] + res.fun)
                 if res.fun is not None else None,
                 "dual_bound": floor,
                 "gap": None if res.mip_gap is None else float(res.mip_gap)})
    return admit, floor, meta
