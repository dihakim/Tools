//go:build linux || darwin

// internal/scanner/network_unix.go
//
// Tested on Linux. macOS also reads /etc/resolv.conf (maintained by the
// system resolver there too), but hasn't been run on an actual Mac as
// part of this project - flagging that honestly rather than claiming
// verified coverage I don't have.
package scanner

import (
	"bufio"
	"os"
	"strings"

	"compliancecheck/internal/model"
	"compliancecheck/internal/netinfo"
)

func scanDNSResolvers() []model.Finding {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		info := model.NewFinding(model.CategoryNetwork, "dns_config_unreadable", "Could not read DNS resolver config", model.SeverityInfo)
		info.Source = "network.dns"
		info.Detail = err.Error()
		return []model.Finding{info}
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				servers = append(servers, parts[1])
			}
		}
	}

	finding := model.NewFinding(model.CategoryNetwork, "dns_resolvers", "Configured DNS resolvers", model.SeverityInfo)
	finding.Source = "network.dns"
	finding.Location = "/etc/resolv.conf"
	details := annotateDNSServers(servers)
	if len(servers) == 0 {
		finding.Detail = "No nameserver entries found."
	} else {
		finding.Detail = summarizeDNSServers(details)
	}
	finding.Evidence["servers"] = servers
	finding.Evidence["server_details"] = details
	return []model.Finding{finding}
}

func summarizeDNSServers(details []map[string]any) string {
	var parts []string
	for _, d := range details {
		s := d["ip"].(string)
		if provider, ok := d["known_provider"].(string); ok {
			s += " (" + provider + ")"
		} else if class, ok := d["classification"].(netinfo.IPClass); ok && class.Valid && class.Scope != "public" {
			s += " (" + class.Scope + ")"
		} else {
			s += " (unrecognized public resolver)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// annotateDNSServers classifies each resolver IP (public/private/etc.) and
// names the operator if it's a well-known public DNS provider - all from
// static embedded data, no live lookups.
func annotateDNSServers(servers []string) []map[string]any {
	var out []map[string]any
	for _, s := range servers {
		entry := map[string]any{"ip": s, "classification": netinfo.Classify(s)}
		if provider, ok := netinfo.KnownDNSProvider(s); ok {
			entry["known_provider"] = provider
		}
		out = append(out, entry)
	}
	return out
}
