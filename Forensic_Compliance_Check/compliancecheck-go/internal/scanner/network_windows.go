//go:build windows

// internal/scanner/network_windows.go
//
// Windows has no equivalent of /etc/resolv.conf to just read - resolver
// config lives in the registry per-adapter. Shelling out to `ipconfig`
// (already present on every Windows install, nothing extra to install)
// and parsing its text output is the pragmatic option here.
//
// IMPORTANT: this has NOT been run on an actual Windows machine as part
// of this project (built and tested on Linux only, cross-compiled for
// Windows). ipconfig's text format is locale-dependent, which this
// parser does not account for - treat this file as a starting point that
// needs real testing on Windows before being trusted, not verified
// working code.
package scanner

import (
	"os/exec"
	"strings"

	"compliancecheck/internal/model"
)

func scanDNSResolvers() []model.Finding {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		info := model.NewFinding(model.CategoryNetwork, "dns_config_unreadable", "Could not read DNS resolver config", model.SeverityInfo)
		info.Source = "network.dns"
		info.Detail = "ipconfig /all failed: " + err.Error()
		return []model.Finding{info}
	}

	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS Servers") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if ip := strings.TrimSpace(parts[1]); ip != "" {
					servers = append(servers, ip)
				}
			}
		} else if len(servers) > 0 && !strings.Contains(line, ":") && line != "" {
			// ipconfig continues a multi-server list on indented follow-up lines
			// with no "DNS Servers" label repeated.
			servers = append(servers, line)
		}
	}

	finding := model.NewFinding(model.CategoryNetwork, "dns_resolvers", "Configured DNS resolvers", model.SeverityInfo)
	finding.Source = "network.dns"
	finding.Location = "ipconfig /all"
	finding.Detail = "UNVERIFIED on real Windows - parser needs testing. " + strings.Join(servers, ", ")
	finding.Evidence["servers"] = servers
	return []model.Finding{finding}
}
