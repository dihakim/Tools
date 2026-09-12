//go:build linux

// internal/scanner/hardware_linux_cpuvuln.go
//
// Reads /sys/devices/system/cpu/vulnerabilities/* - the kernel's own,
// authoritative, continuously-updated report of whether THIS specific CPU
// is affected by and/or mitigated against known speculative-execution
// vulnerabilities (Spectre, Meltdown, MDS, etc.). This is always more
// accurate than trying to match CPU model strings against a static
// vulnerability list, since the kernel already knows the actual
// microcode/mitigation state - the bundled hwintel CVE data is used only
// to add human-readable context (CVE ID, description) alongside what the
// kernel reports, not to make the affected/mitigated determination itself.
package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"compliancecheck/internal/hwintel"
	"compliancecheck/internal/model"
)

// nameToCVEHint maps a subset of the kernel's vulnerability file names to
// the bundled reference data's title, for cross-referencing. Not
// exhaustive - the kernel reports many more (mmio_stale_data, retbleed,
// srbds, etc.) than the small bundled CVE set covers; those still get a
// Finding from the kernel's own report, just without the extra CVE context.
var nameToCVETitle = map[string]string{
	"meltdown":   "Meltdown",
	"spectre_v1": "Spectre (Variant 1)",
	"spectre_v2": "Spectre (Variant 2)",
	"l1tf":       "Foreshadow (L1TF)",
}

func scanCPUVulnerabilities() []model.Finding {
	root := "/sys/devices/system/cpu/vulnerabilities"
	entries, err := os.ReadDir(root)
	if err != nil {
		return []model.Finding{unreadableHW("hw_cpu_vulnerabilities", err)}
	}

	cveByTitle := map[string]hwintel.CPUVulnerability{}
	for _, v := range hwintel.KnownCPUVulnerabilities() {
		cveByTitle[v.Title] = v
	}

	var out []model.Finding
	for _, e := range entries {
		status := readSysAttr(filepath.Join(root, e.Name()))
		if status == "" {
			continue
		}

		sev := model.SeverityClean
		lower := strings.ToLower(status)
		if strings.Contains(lower, "vulnerable") {
			sev = model.SeverityHigh
		} else if strings.HasPrefix(lower, "mitigation") {
			sev = model.SeverityInfo // affected but the kernel reports it's handled
		}

		f := model.NewFinding(model.CategoryHardware, "hw_cpu_vulnerability", "CPU vulnerability: "+e.Name(), sev)
		f.Source = "hardware.cpu_vulnerabilities"
		f.Location = e.Name()
		f.Detail = status
		f.Evidence["status"] = status

		if cveTitle, ok := nameToCVETitle[e.Name()]; ok {
			if cve, ok := cveByTitle[cveTitle]; ok {
				f.Detail += " (" + cve.CVEID + ": " + cve.Description + ")"
				f.Evidence["cve_id"] = cve.CVEID
				f.Evidence["cvss_score"] = cve.CVSSScore
				f.Evidence["mitigation_reference"] = cve.Mitigation
			}
		}

		out = append(out, f)
	}
	if out == nil {
		info := model.NewFinding(model.CategoryHardware, "hw_cpu_vulnerabilities_none", "No CPU vulnerability data available", model.SeverityInfo)
		info.Source = "hardware.cpu_vulnerabilities"
		out = append(out, info)
	}
	return out
}
