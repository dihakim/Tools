// internal/netinfo/netinfo.go
//
// General network-info enrichment, entirely offline:
//   - IP classification: public vs. private vs. loopback vs. link-local vs.
//     CGNAT vs. multicast vs. reserved/documentation ranges, using Go's
//     stdlib net package logic (no live lookups, no internet needed).
//   - Known-DNS-provider lookup: a small embedded table of well-known
//     public DNS resolver IPs and who operates them (Google, Cloudflare,
//     Quad9, OpenDNS, etc.) - this is "who owns what" for DNS servers
//     specifically, done with static data rather than a live WHOIS/RDAP
//     call, so it works with zero internet access. It does NOT attempt
//     general IP WHOIS/ownership lookups - that fundamentally requires a
//     live query against a registry (ARIN/RIPE/APNIC/etc.) and can't be
//     done offline; that gap is intentional, not an oversight.
package netinfo

import (
	"embed"
	"encoding/json"
	"net"
)

//go:embed dns_providers.json
var embedded embed.FS

var dnsProviders map[string]string

func init() {
	dnsProviders = map[string]string{}
	b, err := embedded.ReadFile("dns_providers.json")
	if err != nil {
		return
	}
	var doc struct {
		Resolvers []struct {
			IP       string `json:"ip"`
			Provider string `json:"provider"`
		} `json:"resolvers"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return
	}
	for _, r := range doc.Resolvers {
		dnsProviders[r.IP] = r.Provider
	}
}

// KnownDNSProvider returns the operator name for a well-known public DNS
// resolver IP, if recognized (e.g. "8.8.8.8" -> "Google Public DNS").
func KnownDNSProvider(ip string) (string, bool) {
	p, ok := dnsProviders[ip]
	return p, ok
}

type IPClass struct {
	Valid     bool   `json:"valid"`
	Version   string `json:"version,omitempty"`   // "IPv4" | "IPv6"
	Scope     string `json:"scope,omitempty"`      // public | private | loopback | link_local | multicast | cgnat | documentation | unspecified | broadcast | reserved
	IsPublic  bool   `json:"is_public"`
	Detail    string `json:"detail,omitempty"`
}

// CGNAT range per RFC 6598: 100.64.0.0/10.
var cgnatBlock = mustCIDR("100.64.0.0/10")

// Documentation/example ranges per RFC 5737 / RFC 3849 - never real traffic,
// worth calling out distinctly if seen (usually indicates test/sample data
// or a misconfiguration rather than a live private network).
var docBlocks = []*net.IPNet{
	mustCIDR("192.0.2.0/24"),    // TEST-NET-1
	mustCIDR("198.51.100.0/24"), // TEST-NET-2
	mustCIDR("203.0.113.0/24"),  // TEST-NET-3
	mustCIDR("2001:db8::/32"),   // IPv6 documentation range
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Classify determines what kind of address a string represents. It's pure
// stdlib logic against RFC-defined ranges - no network access, works fully
// offline, and is exact (not a heuristic) for the ranges it covers.
func Classify(ipStr string) IPClass {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return IPClass{Valid: false}
	}

	version := "IPv6"
	if ip.To4() != nil {
		version = "IPv4"
	}

	switch {
	case ip.IsLoopback():
		return IPClass{Valid: true, Version: version, Scope: "loopback", Detail: "Loopback address (this machine, not reachable from elsewhere)"}
	case ip.IsUnspecified():
		return IPClass{Valid: true, Version: version, Scope: "unspecified", Detail: "Unspecified/any address (0.0.0.0 or ::)"}
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return IPClass{Valid: true, Version: version, Scope: "link_local", Detail: "Link-local address (this network segment only, not routed)"}
	case ip.IsMulticast():
		return IPClass{Valid: true, Version: version, Scope: "multicast", Detail: "Multicast address"}
	case ip.Equal(net.IPv4bcast):
		return IPClass{Valid: true, Version: version, Scope: "broadcast", Detail: "IPv4 limited broadcast address"}
	case cgnatBlock.Contains(ip):
		return IPClass{Valid: true, Version: version, Scope: "cgnat", Detail: "Carrier-Grade NAT range (RFC 6598) - typically an ISP's internal network, not directly internet-routable"}
	case inAny(ip, docBlocks):
		return IPClass{Valid: true, Version: version, Scope: "documentation", Detail: "Reserved for documentation/examples (RFC 5737/3849) - should never appear in real traffic"}
	case ip.IsPrivate():
		return IPClass{Valid: true, Version: version, Scope: "private", Detail: "Private address (RFC 1918/4193) - not routable on the public internet"}
	default:
		return IPClass{Valid: true, Version: version, Scope: "public", IsPublic: true, Detail: "Publicly routable address"}
	}
}

func inAny(ip net.IP, blocks []*net.IPNet) bool {
	for _, b := range blocks {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}
