// compat-oracle evaluates DNS filtering requests with AdGuard's own
// urlfilter library, replicating AdGuard Home's decision logic
// (internal/filtering: matchHost, processDNSRewrites) so that the C engine
// of this project can be checked rule-for-rule against the reference.
//
// Usage:
//
//	compat-oracle [-allow LIST]... LIST... < queries > verdicts
//
// Query lines:   host qtype [client-ip|-] [client-name|-] [tags|-]
// Output lines:  host qtype VERDICT...   (same format as `flc batch`)
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// cleanList mimics AdGuard Home's rulelist parser: lines starting with '#'
// or '!' are dropped, the rest is trimmed.
func cleanList(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var out bytes.Buffer
	for _, line := range bytes.Split(data, []byte("\n")) {
		t := bytes.TrimSpace(line)
		if len(t) == 0 || t[0] == '#' || t[0] == '!' {
			continue
		}
		out.Write(t)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func engine(paths []string, firstID int) *urlfilter.DNSEngine {
	var lists []filterlist.Interface
	for i, p := range paths {
		lists = append(lists, filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             rules.ListID(firstID + i),
			RulesText:      cleanList(p),
			IgnoreCosmetic: true,
		}))
	}
	if len(lists) == 0 {
		return nil
	}
	st, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return urlfilter.NewDNSEngine(st)
}

// --- RDATA encoding exactly as AdGuard Home builds the answers -------------

var strToSVCBKey = map[string]dns.SVCBKey{
	"alpn": dns.SVCB_ALPN, "ech": dns.SVCB_ECHCONFIG, "ipv4hint": dns.SVCB_IPV4HINT,
	"ipv6hint": dns.SVCB_IPV6HINT, "mandatory": dns.SVCB_MANDATORY,
	"no-default-alpn": dns.SVCB_NO_DEFAULT_ALPN, "port": dns.SVCB_PORT, "echconfig": dns.SVCB_ECHCONFIG,
}

func svcbValue(k, v string) dns.SVCBKeyValue {
	switch k {
	case "alpn":
		return &dns.SVCBAlpn{Alpn: []string{v}}
	case "ech":
		b, err := base64.RawStdEncoding.DecodeString(v)
		if err != nil {
			return nil
		}
		return &dns.SVCBECHConfig{ECH: b}
	case "echconfig":
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil
		}
		return &dns.SVCBECHConfig{ECH: b}
	case "ipv4hint":
		ip := net.ParseIP(v)
		if ip4 := ip.To4(); ip == nil || ip4 == nil {
			return nil
		}
		return &dns.SVCBIPv4Hint{Hint: []net.IP{ip}}
	case "ipv6hint":
		ip := net.ParseIP(v)
		if ip == nil {
			return nil
		}
		return &dns.SVCBIPv6Hint{Hint: []net.IP{ip}}
	case "mandatory":
		c, ok := strToSVCBKey[v]
		if !ok {
			return nil
		}
		return &dns.SVCBMandatory{Code: []dns.SVCBKey{c}}
	case "no-default-alpn":
		return &dns.SVCBNoDefaultAlpn{}
	case "port":
		p, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil
		}
		return &dns.SVCBPort{Port: uint16(p)}
	case "dohpath":
		return &dns.SVCBDoHPath{Template: v}
	}
	return nil
}

func rdata(rrtype rules.RRType, v rules.RRValue) (string, bool) {
	hdr := dns.RR_Header{Name: ".", Rrtype: rrtype, Class: dns.ClassINET, Ttl: 10}
	var rr dns.RR
	switch rrtype {
	case dns.TypeA:
		ip := v.(netip.Addr)
		rr = &dns.A{Hdr: hdr, A: ip.AsSlice()}
	case dns.TypeAAAA:
		ip := v.(netip.Addr)
		rr = &dns.AAAA{Hdr: hdr, AAAA: ip.AsSlice()}
	case dns.TypePTR:
		rr = &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(v.(string))}
	case dns.TypeTXT:
		rr = &dns.TXT{Hdr: hdr, Txt: []string{v.(string)}}
	case dns.TypeMX:
		mx := v.(*rules.DNSMX)
		rr = &dns.MX{Hdr: hdr, Preference: mx.Preference, Mx: dns.Fqdn(mx.Exchange)}
	case dns.TypeSRV:
		s := v.(*rules.DNSSRV)
		rr = &dns.SRV{Hdr: hdr, Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: dns.Fqdn(s.Target)}
	case dns.TypeHTTPS, dns.TypeSVCB:
		s := v.(*rules.DNSSVCB)
		svcb := dns.SVCB{Hdr: hdr, Priority: s.Priority, Target: dns.Fqdn(s.Target)}
		for k, val := range s.Params {
			if kv := svcbValue(k, val); kv != nil {
				svcb.Value = append(svcb.Value, kv)
			}
		}
		if rrtype == dns.TypeHTTPS {
			rr = &dns.HTTPS{SVCB: svcb}
		} else {
			rr = &svcb
		}
	default:
		return "", false
	}
	buf := make([]byte, 4096)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return "ERR", true
	}
	return hex.EncodeToString(buf[11:off]), true
}

func decide(allow, block *urlfilter.DNSEngine, host string, qtype uint16, ip netip.Addr, name string, tags []string) string {
	req := &urlfilter.DNSRequest{
		Hostname:          host,
		ClientTags:        container.NewSortedSliceSet(tags...),
		ClientIP:          ip,
		ClientIdentifiers: container.NewSortedSliceSet(name),
		DNSType:           qtype,
	}
	if allow != nil {
		if _, ok := allow.MatchRequest(req); ok {
			return "ALLOWLIST"
		}
	}
	if block == nil {
		return "NONE"
	}
	res, matched := block.MatchRequest(req)
	if *explain {
		for _, nr := range res.NetworkRules {
			fmt.Fprintf(os.Stderr, "    net: %s\n", nr.Text())
		}
		for _, hr := range append(res.HostRulesV4, res.HostRulesV6...) {
			fmt.Fprintf(os.Stderr, "    host: %s\n", hr.Text())
		}
		if res.NetworkRule != nil {
			fmt.Fprintf(os.Stderr, "    basic: %s\n", res.NetworkRule.Text())
		}
		for _, nr := range res.DNSRewrites() {
			fmt.Fprintf(os.Stderr, "    rewrite: %s\n", nr.Text())
		}
	}

	// processDNSResultRewrites
	if dnsr := res.DNSRewrites(); len(dnsr) > 0 {
		resp := map[rules.RRType][]rules.RRValue{}
		out := ""
		for _, nr := range dnsr {
			dr := nr.DNSRewrite
			if dr.NewCNAME != "" {
				out = "REWRITE_CNAME " + strings.ToLower(dr.NewCNAME)
				if dr.NewCNAME == host {
					out = "SELF"
				}
				break
			}
			if dr.RCode != dns.RcodeSuccess {
				out = fmt.Sprintf("REWRITE_RCODE %d", dr.RCode)
				break
			}
			resp[dr.RRType] = append(resp[dr.RRType], dr.Value)
		}
		if out != "SELF" {
			if out != "" {
				return out
			}
			var rrs []string
			for _, v := range resp[qtype] {
				if v == nil {
					continue
				}
				if h, ok := rdata(qtype, v); ok {
					rrs = append(rrs, fmt.Sprintf("%d:%s", qtype, h))
				}
			}
			sort.Strings(rrs)
			return strings.TrimSpace("REWRITE_RRS " + strings.Join(rrs, " "))
		}
	}
	if !matched {
		return "NONE"
	}
	if res.NetworkRule != nil {
		if res.NetworkRule.Whitelist {
			return "ALLOW"
		}
		return "BLOCK"
	}
	pick := func(hr []*rules.HostRule) string {
		var ips []string
		seen := map[string]bool{}
		for _, r := range hr {
			s := r.IP.Unmap().String()
			if r.IP.Is6() {
				s = r.IP.String()
			}
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
		}
		sort.Strings(ips)
		return "BLOCK_HOSTS " + strings.Join(ips, " ")
	}
	if qtype == dns.TypeA && res.HostRulesV4 != nil {
		return pick(res.HostRulesV4)
	}
	if qtype == dns.TypeAAAA && res.HostRulesV6 != nil {
		return pick(res.HostRulesV6)
	}
	if len(res.HostRulesV4) != 0 || len(res.HostRulesV6) != 0 {
		return "BLOCK"
	}
	return "NONE"
}

var explain = flag.Bool("explain", false, "print all matching rules")

func main() {
	var allowLists listFlag
	flag.Var(&allowLists, "allow", "allowlist file (repeatable)")
	flag.Parse()
	block := engine(flag.Args(), 1)
	allow := engine(allowLists, 1000)

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(f[0]), ".")
		qtype := uint16(1)
		if len(f) > 1 {
			if t, ok := dns.StringToType[strings.ToUpper(f[1])]; ok {
				qtype = t
			} else if n, err := strconv.Atoi(f[1]); err == nil {
				qtype = uint16(n)
			}
		}
		var ip netip.Addr
		name := ""
		var tags []string
		if len(f) > 2 && f[2] != "-" {
			ip, _ = netip.ParseAddr(f[2])
		}
		if len(f) > 3 && f[3] != "-" {
			name = f[3]
		}
		if len(f) > 4 && f[4] != "-" {
			tags = strings.Split(f[4], ",")
		}
		fmt.Fprintf(w, "%s %d %s\n", host, qtype, decide(allow, block, host, qtype, ip, name, tags))
	}
}
