// internal/webui/checks.go
//
// Defines the "check families" a UI can let someone pick per category
// (e.g. within Storage: file signature / PII / encoded content / cipher /
// entropy), and applies that selection to a finished scan's findings by
// matching Finding.Subtype prefixes.
//
// This is deliberately a POST-SCAN filter, not a way to skip work: every
// check still runs, and only what's returned/displayed is restricted. That
// keeps the implementation simple (no per-scanner partial-execution mode
// to build and maintain) while still delivering what was actually asked
// for - control over what shows up in the report. The one known trade-off,
// stated plainly: a file's "clean" marker reflects the FULL scan, not the
// filtered check set - deselecting the PII check doesn't retroactively
// mark a PII-only-flagged file as clean. Documented rather than hidden.
package webui

import "strings"

// CheckDefinition is one selectable check family within a category.
type CheckDefinition struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Prefixes    []string `json:"-"`
}

var storageChecks = []CheckDefinition{
	{ID: "file_signature", Label: "File signature mismatch", Prefixes: []string{"file_signature_mismatch"}},
	{ID: "pii", Label: "PII detection", Prefixes: []string{"pii_"}},
	{ID: "encoded_content", Label: "Encoded content (base64/hex/etc.)", Prefixes: []string{"encoded_content_"}},
	{ID: "cipher", Label: "Cipher detection/cracking", Prefixes: []string{"cipher_cracked_", "unrecognized_language"}},
	{ID: "entropy", Label: "High-entropy content", Prefixes: []string{"high_entropy_content", "entropy_spike"}},
	{ID: "extraction", Label: "Text extraction issues", Prefixes: []string{"extraction_"}},
	{ID: "ssh", Label: "SSH key security audit", Prefixes: []string{"ssh_"}},
	{ID: "suid", Label: "SUID/SGID binaries", Prefixes: []string{"suid_"}},
	{ID: "credential_files", Label: "Credential files (.aws, .netrc, etc.)", Prefixes: []string{"credential_file_"}},
	{ID: "custom_search", Label: "Custom name/term search", Prefixes: []string{"custom_name_search", "custom_term_search"}},
}

var networkChecks = []CheckDefinition{
	{ID: "interfaces", Label: "Network interfaces", Prefixes: []string{"interface"}},
	{ID: "hosts_file", Label: "Hosts file", Prefixes: []string{"hosts_entry", "hosts_file_"}},
	{ID: "dns", Label: "DNS resolvers", Prefixes: []string{"dns_"}},
	{ID: "listening_ports", Label: "Listening ports", Prefixes: []string{"listening_port"}},
	{ID: "wifi", Label: "Saved WiFi profiles", Prefixes: []string{"wifi_"}},
	{ID: "firewall", Label: "Firewall rules", Prefixes: []string{"firewall_"}},
}

var softwareChecks = []CheckDefinition{
	{ID: "os_info", Label: "OS identity", Prefixes: []string{"os_identity"}},
	{ID: "users", Label: "Local user accounts", Prefixes: []string{"local_user_account", "users_"}},
	{ID: "processes", Label: "Running processes", Prefixes: []string{"process", "processes_"}},
	{ID: "packages", Label: "Installed software", Prefixes: []string{"installed_packages", "package_", "packages_"}},
	{ID: "browsers", Label: "Browser history & bookmarks", Prefixes: []string{"browser_"}},
	{ID: "persistence", Label: "Persistence/autostart (cron, systemd, etc.)", Prefixes: []string{"persistence_"}},
}

var hardwareChecks = []CheckDefinition{
	{ID: "cpu", Label: "CPU", Prefixes: []string{"cpu"}},
	{ID: "memory", Label: "Memory", Prefixes: []string{"memory"}},
	{ID: "storage_volumes", Label: "Storage volumes", Prefixes: []string{"storage_volume", "storage_unreadable"}},
	{ID: "usb", Label: "USB devices", Prefixes: []string{"usb_"}},
	{ID: "pci", Label: "PCI devices", Prefixes: []string{"pci_"}},
	{ID: "cpu_vulnerabilities", Label: "CPU vulnerabilities (Spectre/Meltdown/etc.)", Prefixes: []string{"hw_cpu_vulnerabilit"}},
	{ID: "tpm", Label: "TPM", Prefixes: []string{"tpm_"}},
	{ID: "secure_boot", Label: "Secure Boot", Prefixes: []string{"secure_boot_"}},
	{ID: "encryption", Label: "Disk encryption", Prefixes: []string{"disk_encryption"}},
}

var allChecksByCategory = map[string][]CheckDefinition{
	"files":    storageChecks,
	"network":  networkChecks,
	"software": softwareChecks,
	"hardware": hardwareChecks,
}

// housekeepingSubtypes are always kept regardless of check selection -
// they're not "a check" a person would opt out of, just scan bookkeeping.
var housekeepingSubtypes = []string{"clean_file", "scan_error"}

// resolvePrefixes turns a category's selected check IDs into the concrete
// subtype prefixes to keep. Empty selection = keep everything for that
// category (no filtering applied).
func resolvePrefixes(category string, selectedIDs []string) (prefixes []string, filterActive bool) {
	if len(selectedIDs) == 0 {
		return nil, false
	}
	defs := allChecksByCategory[category]
	selected := map[string]bool{}
	for _, id := range selectedIDs {
		selected[id] = true
	}
	for _, d := range defs {
		if selected[d.ID] {
			prefixes = append(prefixes, d.Prefixes...)
		}
	}
	prefixes = append(prefixes, housekeepingSubtypes...)
	return prefixes, true
}

func subtypeAllowed(subtype string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(subtype, p) || subtype == p {
			return true
		}
	}
	return false
}
