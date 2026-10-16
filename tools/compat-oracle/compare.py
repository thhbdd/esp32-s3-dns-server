#!/usr/bin/env python3
"""Differential test: this project's filter engine vs AdGuard urlfilter.

    compare.py --flc build-host/flc --oracle /path/to/compat-oracle \
               [--lists L1 L2 ...] [--seeds 10] [--workdir DIR]

1. Torture mode: random rule interactions (gen_torture.py) for N seeds.
2. Real-list mode (optional): compiles the given lists and compares a large
   query corpus generated from them (gen_queries.py).

Mismatches are classified; documented divergences (docs/FILTER_COMPAT.md)
are reported separately.  Exit status is non-zero if any unexplained
mismatch remains.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def run(cmd, stdin=None, stdout=None):
    r = subprocess.run(cmd, stdin=stdin, stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        sys.stderr.write("command failed: %s\n%s\n" % (" ".join(cmd), r.stderr))
        sys.exit(2)
    return r


def explain_ref(oracle, query, lists, allow):
    cmd = [oracle, "-explain"] + sum([["-allow", a] for a in allow], []) + lists
    r = subprocess.run(cmd, input=query + "\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return r.stderr


def without_badfiltered(lists, allow, bf_rules, workdir):
    """Copies of the lists without the $badfilter rules and the rules they
    negate: what every $badfilter taking effect means (documented semantics).
    Rules with $dnsrewrite stay: rewrites ignore $badfilter in AdGuard."""
    drop = set()
    for b in bf_rules:
        if "dnsrewrite" in b:
            continue
        pat, _, mods = b.partition("$")
        rest = [m for m in mods.split(",") if m.strip() != "badfilter"]
        drop.add(b)
        drop.add(pat + ("$" + ",".join(rest) if rest else ""))
    out = []
    for i, path in enumerate(lists + allow):
        dst = os.path.join(workdir, "nobf%d.txt" % i)
        with open(path, errors="surrogateescape") as f, open(dst, "w", errors="surrogateescape") as g:
            for line in f:
                if line.strip() not in drop:
                    g.write(line)
        out.append(dst)
    return out[:len(lists)], out[len(lists):]


def classify(ours, ref, expl, oracle, query, lists, allow, workdir):
    bf = re.findall(r"net: (.*badfilter.*)", expl)
    if len(bf) >= 2:
        # confirmed only if the reference gives our answer once all of them
        # apply (or the rest is a D3 rewrite-order difference)
        l2, a2 = without_badfiltered(lists, allow, [b.strip() for b in bf], workdir)
        cmd = [oracle] + sum([["-allow", a] for a in a2], []) + l2
        r = subprocess.run(cmd, input=query + "\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ref2 = r.stdout.strip()
        expl2 = explain_ref(oracle, query, l2, a2) if ref2 != ours.strip() else ""
        if ref2 == ours.strip() or is_d3(ours, ref2, expl2) or is_d4(ours, ref2, expl2):
            return "D2 multiple $badfilter rules match (urlfilter keeps the negated rules)"
        return None
    if is_d3(ours, ref, expl):
        return "D3 conflicting $dnsrewrite rules (AdGuard order is index dependent)"
    if is_d4(ours, ref, expl):
        return "D4 MX/SRV/SVCB/HTTPS rewrite exception (never matches in AdGuard)"
    return None


def is_d4(ours, ref, expl):
    """ref keeps MX/SRV/SVCB/HTTPS rewrite records that an exception removed here"""
    if " REWRITE_RRS" not in ours or " REWRITE_RRS" not in ref:
        return False
    o = set(ours.split("REWRITE_RRS", 1)[1].split())
    r = set(ref.split("REWRITE_RRS", 1)[1].split())
    extra = r - o
    if not extra or not o <= r or any(x.split(":")[0] not in ("15", "33", "64", "65") for x in extra):
        return False
    return re.search(r"net: @@.*dnsrewrite=NOERROR;(MX|SRV|SVCB|HTTPS);", expl) is not None


def is_d3(ours, ref, expl):
    """Both answers are rewrites and several rewrites compete for the answer
    (CNAME and RCODE rewrites each decide it alone; which one AdGuard takes
    depends on its index order)."""
    if "REWRITE_" not in ours or "REWRITE_" not in ref:
        return False
    rw = re.findall(r"rewrite: (.*)", expl)
    kinds, decisive = set(), 0
    for r in rw:
        v = r.split("dnsrewrite", 1)[1]
        if "CNAME" in v or re.match(r"=[a-z]", v):
            kinds.add("cname")
            decisive += 1
        elif re.search(r"=(NXDOMAIN|REFUSED|SERVFAIL)", v):
            kinds.add("rcode")
            decisive += 1
        else:
            kinds.add("rr")
    return len(rw) >= 2 and (len(kinds) >= 2 or decisive >= 2)


def compare(flc, oracle, image, lists, allow, queries, label, workdir):
    ours = run([flc, "batch", image], stdin=open(queries)).stdout.splitlines()
    cmd = [oracle] + sum([["-allow", a] for a in allow], []) + lists
    ref = run(cmd, stdin=open(queries)).stdout.splitlines()
    qs = open(queries).read().splitlines()
    assert len(ours) == len(ref) == len(qs), "output length mismatch"
    classes = {}
    unexplained = []
    for q, o, r in zip(qs, ours, ref):
        if o == r:
            continue
        expl = explain_ref(oracle, q, lists, allow)
        c = classify(o, r, expl, oracle, q, lists, allow, workdir)
        if c:
            classes[c] = classes.get(c, 0) + 1
        else:
            unexplained.append((q, o, r, expl))
    print("%-24s %8d queries, %6d identical, documented divergences: %s, unexplained: %d" %
          (label, len(qs), len(qs) - sum(classes.values()) - len(unexplained),
           ", ".join("%s=%d" % (k.split()[0], v) for k, v in sorted(classes.items())) or "none", len(unexplained)))
    for q, o, r, e in unexplained[:5]:
        print("  query: %s\n    ours: %s\n    ref:  %s\n%s" % (q, o, r, e))
    return len(unexplained)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flc", required=True)
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--lists", nargs="*", default=[])
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--max-queries", type=int, default=200000)
    ap.add_argument("--workdir")
    a = ap.parse_args()
    wd = a.workdir or tempfile.mkdtemp(prefix="compat-")
    os.makedirs(wd, exist_ok=True)
    bad = 0
    for seed in range(1, a.seeds + 1):
        run([sys.executable, os.path.join(HERE, "gen_torture.py"), wd, "--seed", str(seed), "--rules", "300"])
        lists = [os.path.join(wd, "torture.txt")]
        allow = [os.path.join(wd, "torture_allow.txt")]
        img = os.path.join(wd, "t.img")
        run([a.flc, "compile", "-o", img, lists[0], "--allow", allow[0]])
        bad += compare(a.flc, a.oracle, img, lists, allow, os.path.join(wd, "torture_q.txt"), "torture seed %d" % seed,
                       wd)
    if a.lists:
        q = os.path.join(wd, "real_q.txt")
        with open(q, "w") as f:
            run([sys.executable, os.path.join(HERE, "gen_queries.py"), "--max", str(a.max_queries)] + a.lists,
                stdout=f)
        img = os.path.join(wd, "real.img")
        run([a.flc, "compile", "-o", img] + a.lists)
        bad += compare(a.flc, a.oracle, img, a.lists, [], q, "real lists", wd)
    print("RESULT: %s" % ("PASS" if bad == 0 else "FAIL (%d unexplained)" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
