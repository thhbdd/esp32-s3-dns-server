#!/usr/bin/env python3
"""Generates a differential-test query corpus from filter lists.

For every rule it derives hostnames that should and should not match
(the domain itself, sub-domains, parents, look-alikes, wildcard
instantiations), mixes query types and client identities, and writes
"host qtype ip name tags" lines for `flc batch` and `compat-oracle`.

    gen_queries.py [--max N] [--seed S] LIST... > queries.txt
"""
import argparse
import random
import re
import sys

QTYPES = ["A"] * 6 + ["AAAA"] * 3 + ["HTTPS", "MX", "TXT", "CNAME", "PTR", "SRV", "ANY"]
CLIENTS = [("-", "-", "-"), ("192.168.1.10", "-", "-"), ("192.168.1.20", "kid", "user_child"),
           ("10.0.0.5", "laptop", "device_laptop,os_linux"), ("fd00::5", "phone", "device_phone,os_android"),
           ("1.2.3.4", "-", "-")]
ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"

DOMAIN_RE = re.compile(r"^[a-z0-9_.-]+$")


def rnd(n):
    return "".join(random.choice(ALNUM) for _ in range(n))


def variants(d):
    out = [d, "www." + d, rnd(5) + "." + d, "a" + d, d + ".cn"]
    if "." in d:
        out.append(d.split(".", 1)[1])
    return out


def from_pattern(p):
    p = p.split("$", 1)[0]
    if p.startswith("@@"):
        p = p[2:]
    if p.startswith("/") and p.endswith("/") and len(p) > 2:
        # crude instantiation of simple regexes
        r = p[1:-1]
        r = r.replace("^", "").replace("$", "").replace("\\.", ".").replace("(\\S+.)?", "x.")
        r = re.sub(r"\[[^\]]*\]\{?\d*,?\d*\}?[+*]?", lambda m: rnd(3), r)
        r = re.sub(r"[\\()|?+*{}]", "", r)
        return [r.lower(), "x." + r.lower()] if r else []
    p = p.lstrip("|").rstrip("|").replace("^", "")
    if p.startswith("://"):
        p = p[3:]
    hosts = []
    for _ in range(2):
        h = re.sub(r"\*", lambda m: rnd(random.randint(0, 4)), p).strip(".")
        if h:
            hosts.append(h.lower())
    return hosts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=400000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("lists", nargs="+")
    a = ap.parse_args()
    random.seed(a.seed)
    hosts = []
    for path in a.lists:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line[0] in "!#":
                    continue
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^[0-9a-fA-F:.]+$", parts[0]):
                    for h in parts[1:]:
                        if h.startswith("#"):
                            break
                        hosts += variants(h.lower())
                    continue
                m = re.match(r"^(@@)?\|\|([a-z0-9_.-]+)\^", line)
                if m:
                    hosts += variants(m.group(2))
                    continue
                if DOMAIN_RE.match(line):
                    hosts += variants(line)
                    continue
                hosts += from_pattern(line)
    random.shuffle(hosts)
    hosts += [rnd(8) + ".example.com" for _ in range(2000)]
    hosts += ["ad%d.%s.com" % (random.randint(0, 999), rnd(5)) for _ in range(2000)]
    hosts += ["1.2.3.4", "88.208.22.3", "139.45.197.245", "localhost", "com", "cn"]
    seen = set()
    n = 0
    for h in hosts:
        if not h or len(h) > 253 or " " in h:
            continue
        q = random.choice(QTYPES)
        key = (h, q)
        if key in seen:
            continue
        seen.add(key)
        ip, name, tags = random.choice(CLIENTS)
        sys.stdout.write("%s %s %s %s %s\n" % (h, q, ip, name, tags))
        n += 1
        if n >= a.max:
            break


if __name__ == "__main__":
    main()
