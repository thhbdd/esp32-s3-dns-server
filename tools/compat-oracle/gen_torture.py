#!/usr/bin/env python3
"""Generates a randomized "torture" rule list exercising rule interactions
(exceptions, $important, $badfilter, $dnsrewrite and its exceptions,
$client, $ctag, $dnstype, $denyallow, hosts syntax, wildcards, regexes)
over a small domain universe, plus a query corpus for it.

    gen_torture.py OUTDIR [--rules N] [--seed S]
writes OUTDIR/torture.txt, OUTDIR/torture_allow.txt, OUTDIR/torture_q.txt
"""
import argparse
import os
import random

DOMAINS = ["example.com", "ads.example.com", "a.b.example.com", "tracker.net", "cdn.tracker.net",
           "example.org", "good.org", "x.good.org", "mail.example.com", "_srv._tcp.example.com",
           "ad1.site.io", "ad22.site.io", "site.io", "img.ad.site.io", "1.2.3.4", "10.0.0.1"]
CLIENT_VALS = ["192.168.1.10", "192.168.1.0/24", "~192.168.1.10", "10.0.0.0/8", "'kid'", "~kid",
               "fd00::/8", "laptop", "\"phone\""]
CTAGS = ["device_phone", "~device_phone", "user_child", "os_linux|device_laptop", "~os_android"]
TYPES = ["A", "AAAA", "~A", "HTTPS", "A|AAAA", "MX", "~AAAA", "TXT"]
REWRITES = ["1.2.3.4", "1.2.3.5", "::1", "2001:db8::2", "NXDOMAIN", "REFUSED", "SERVFAIL",
            "NOERROR", "example.net", "good.org", "NOERROR;A;5.6.7.8", "NOERROR;AAAA;::5",
            "NOERROR;MX;10 mail.example.net", "NOERROR;TXT;hello world", "NOERROR;TXT;v=spf1 -all",
            "NOERROR;PTR;ptr.example.net.", "NOERROR;SRV;10 20 443 srv.example.net",
            "NOERROR;HTTPS;1 . alpn=h2", "NOERROR;HTTPS;2 svc.example.net port=8443 ipv4hint=1.1.1.1",
            "NOERROR;SVCB;3 svc.example.net mandatory=alpn alpn=h3 ech=AEj+DQBE",
            "NOERROR;CNAME;cname.example.net", "NOERROR;NS;ns.example.net", ""]


def pattern(d):
    shapes = ["||%s^", "|%s^", "||%s^|", "%s", "||*.%s^", ".%s^", "*.%s^", "://%s^", "%s^", "||%s"]
    return random.choice(shapes) % d


def modifiers(allow_dnsrewrite=True):
    mods = []
    if random.random() < 0.3:
        mods.append("important")
    if random.random() < 0.25:
        mods.append("client=" + "|".join(random.sample(CLIENT_VALS, random.randint(1, 2))))
    if random.random() < 0.2:
        mods.append("ctag=" + random.choice(CTAGS))
    if random.random() < 0.25:
        mods.append("dnstype=" + random.choice(TYPES))
    if random.random() < 0.1:
        mods.append("denyallow=" + random.choice(["good.org", "example.org|tracker.net", "site.io"]))
    if allow_dnsrewrite and random.random() < 0.25:
        v = random.choice(REWRITES)
        mods.append("dnsrewrite" + ("=" + v if v else ""))
    return mods


def rule():
    r = random.random()
    if r < 0.08:
        ips = random.sample(["0.0.0.0", "127.0.0.1", "1.2.3.4", "::", "::1", "2001:db8::1"], 1)[0]
        return "%s %s" % (ips, " ".join(random.sample(DOMAINS, random.randint(1, 3))))
    if r < 0.12:
        return random.choice(["/^ad[0-9]+\\.site\\.io$/", "/tracker/", "/^(\\S+\\.)?example\\.(com|org)$/",
                              "/^1\\.2\\.3\\.[0-9]+$/", "/good/$dnstype=AAAA", "/^x\\./$important"])
    if r < 0.18:
        return random.choice(["||ad*.site.io^", "||*ads*^", "||img.*.site.io^", "*$client=10.0.0.5",
                              "||*^$denyallow=example.com|good.org", "ad*.site.io^$dnstype=A"])
    d = random.choice(DOMAINS)
    p = pattern(d)
    wl = random.random() < 0.3
    mods = modifiers()
    if random.random() < 0.12:
        mods.append("badfilter")
    text = ("@@" if wl else "") + p
    if mods:
        text += "$" + ",".join(mods)
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--rules", type=int, default=400)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    random.seed(a.seed)
    rules = [rule() for _ in range(a.rules)]
    # badfilter twins of existing rules
    for r in random.sample(rules, len(rules) // 10):
        if "$" in r and not r.startswith("/"):
            rules.append(r + ",badfilter")
        elif not r[0].isdigit():
            rules.append(r + "$badfilter")
    random.shuffle(rules)
    with open(os.path.join(a.outdir, "torture.txt"), "w") as f:
        f.write("! torture list\n" + "\n".join(rules) + "\n")
    with open(os.path.join(a.outdir, "torture_allow.txt"), "w") as f:
        f.write("||good.org^\n0.0.0.0 cdn.tracker.net\n||x.good.org^$client=192.168.1.10\n")
    clients = [("-", "-", "-"), ("192.168.1.10", "-", "-"), ("192.168.1.20", "kid", "user_child"),
               ("10.0.0.5", "laptop", "device_laptop,os_linux"), ("fd00::5", "phone", "device_phone,os_android")]
    qtypes = ["A", "AAAA", "HTTPS", "MX", "TXT", "PTR", "SRV", "SVCB", "NS", "CNAME"]
    hosts = DOMAINS + ["www." + d for d in DOMAINS] + ["zz" + d for d in DOMAINS] + ["foo.ads.bar", "ads.foo",
                                                                                     "img.q.site.io", "ad7.site.io"]
    with open(os.path.join(a.outdir, "torture_q.txt"), "w") as f:
        for h in hosts:
            for q in qtypes:
                for c in clients:
                    f.write("%s %s %s %s %s\n" % (h, q, *c))


if __name__ == "__main__":
    main()
