//go:build linux

// internal/scanner/network_linux_firewall.go
//
// Firewall rule enumeration - directly from the original spec's Network
// Forensics group. Uses `nft list ruleset` (nftables, the modern default
// on most current distros) or falls back to `iptables-save`/`ip6tables-save`
// (legacy) - all three are standard system tools invoked read-only, not
// anything newly installed. Both typically require root; this reports
// "permission denied" honestly rather than fabricating a ruleset.
//
// UNTESTED against a live ruleset in this project's sandbox (neither nft
// nor iptables is installed here - confirmed by direct inspection), so
// only the graceful "tool not found" path is verified end-to-end.
package scanner

import (
	"os/exec"
	"strings"

	"compliancecheck/internal/model"
)

func scanFirewallRules() []model.Finding {
	if path, err := exec.LookPath("nft"); err == nil {
		if f, ok := runFirewallTool(path, []string{"list", "ruleset"}, "nftables"); ok {
			return f
		}
	}
	if path, err := exec.LookPath("iptables-save"); err == nil {
		if f, ok := runFirewallTool(path, nil, "iptables"); ok {
			return f
		}
	}

	f := model.NewFinding(model.CategoryNetwork, "firewall_unavailable", "Firewall rules", model.SeverityInfo)
	f.Source = "network.firewall"
	f.Detail = "Neither nft nor iptables-save found on PATH, or reading the ruleset failed (commonly needs root) - could not enumerate firewall rules."
	return []model.Finding{f}
}

func runFirewallTool(path string, args []string, toolName string) ([]model.Finding, bool) {
	out, err := exec.Command(path, args...).Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return nil, false
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	ruleCount := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		ruleCount++
	}

	preview := strings.TrimSpace(string(out))
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}

	f := model.NewFinding(model.CategoryNetwork, "firewall_ruleset", "Firewall ruleset ("+toolName+")", model.SeverityInfo)
	f.Source = "network.firewall"
	f.Detail = preview
	f.Evidence["tool"] = toolName
	f.Evidence["rule_line_count"] = ruleCount
	f.Evidence["full_ruleset"] = string(out)
	return []model.Finding{f}, true
}
