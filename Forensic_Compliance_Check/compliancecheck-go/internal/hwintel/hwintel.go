// internal/hwintel/hwintel.go
//
// Static hardware-identity lookups, all offline: MAC OUI vendor registry,
// USB vendor/product ID registry, PCI vendor/device ID registry, and a
// small known-CPU-vulnerability database (Spectre/Meltdown/Foreshadow).
// Sourced from a hardware intelligence export (~10,000 entries per
// registry) - this is real reference data, not a live API, so coverage
// is necessarily a snapshot rather than exhaustive/current. Every lookup
// degrades gracefully to "not found" rather than guessing.
package hwintel

import (
	"embed"
	"encoding/json"
	"strings"
)

//go:embed mac_vendors.json usb_registry.json pci_registry.json hardware_vulnerabilities.json software_intel.json
var embedded embed.FS

type macEntry struct {
	Prefix string `json:"prefix"`
	Vendor string `json:"vendor"`
}

type usbEntry struct {
	VendorID    string `json:"vendor_id"`
	ProductID   string `json:"product_id"`
	VendorName  string `json:"vendor_name"`
	ProductName string `json:"product_name"`
	DeviceClass string `json:"device_class"`
}

type pciEntry struct {
	VendorID    string `json:"vendor_id"`
	DeviceID    string `json:"device_id"`
	VendorName  string `json:"vendor_name"`
	DeviceName  string `json:"device_name"`
	DeviceClass string `json:"device_class"`
}

type CPUVulnerability struct {
	CVEID              string `json:"cve_id"`
	Title              string `json:"title"`
	Description        string `json:"description"`
	CVSSScore          float64 `json:"cvss_score"`
	CVSSSeverity       string `json:"cvss_severity"`
	Mitigation         string `json:"mitigation"`
	AffectedCompaniesRaw string `json:"affected_companies"`
}

var (
	macByPrefix map[string]string
	usbByID     map[string]usbEntry
	pciByID     map[string]pciEntry
	cpuVulns    []CPUVulnerability
)

func init() {
	macByPrefix = map[string]string{}
	if b, err := embedded.ReadFile("mac_vendors.json"); err == nil {
		var entries []macEntry
		if json.Unmarshal(b, &entries) == nil {
			for _, e := range entries {
				macByPrefix[normalizeHex(e.Prefix)] = e.Vendor
			}
		}
	}

	usbByID = map[string]usbEntry{}
	if b, err := embedded.ReadFile("usb_registry.json"); err == nil {
		var entries []usbEntry
		if json.Unmarshal(b, &entries) == nil {
			for _, e := range entries {
				usbByID[normalizeHex(e.VendorID)+":"+normalizeHex(e.ProductID)] = e
			}
		}
	}

	pciByID = map[string]pciEntry{}
	if b, err := embedded.ReadFile("pci_registry.json"); err == nil {
		var entries []pciEntry
		if json.Unmarshal(b, &entries) == nil {
			for _, e := range entries {
				pciByID[normalizeHex(e.VendorID)+":"+normalizeHex(e.DeviceID)] = e
			}
		}
	}

	if b, err := embedded.ReadFile("hardware_vulnerabilities.json"); err == nil {
		json.Unmarshal(b, &cpuVulns)
	}
}

func normalizeHex(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.TrimPrefix(s, "0X")
	return s
}

// LookupMACVendor takes a MAC address (any common separator) and returns
// the OUI vendor name for its first 3 bytes, if known.
func LookupMACVendor(mac string) (string, bool) {
	norm := normalizeHex(mac)
	if len(norm) < 6 {
		return "", false
	}
	v, ok := macByPrefix[norm[:6]]
	return v, ok
}

// LookupUSBDevice takes vendor/product IDs (4 hex digits each, any case,
// with or without "0x") and returns registry info, if known.
func LookupUSBDevice(vendorID, productID string) (usbEntry, bool) {
	e, ok := usbByID[normalizeHex(vendorID)+":"+normalizeHex(productID)]
	return e, ok
}

// LookupPCIDevice takes vendor/device IDs and returns registry info, if known.
func LookupPCIDevice(vendorID, deviceID string) (pciEntry, bool) {
	e, ok := pciByID[normalizeHex(vendorID)+":"+normalizeHex(deviceID)]
	return e, ok
}

func (e usbEntry) VendorNameOr(fallback string) string {
	if e.VendorName != "" {
		return e.VendorName
	}
	return fallback
}
func (e usbEntry) ProductNameOr(fallback string) string {
	if e.ProductName != "" {
		return e.ProductName
	}
	return fallback
}
func (e pciEntry) VendorNameOr(fallback string) string {
	if e.VendorName != "" {
		return e.VendorName
	}
	return fallback
}
func (e pciEntry) DeviceNameOr(fallback string) string {
	if e.DeviceName != "" {
		return e.DeviceName
	}
	return fallback
}

// KnownCPUVulnerabilities returns the small bundled reference set
// (Spectre/Meltdown/Foreshadow-class hardware vulnerabilities) - this is
// NOT a live/current CVE feed, just enough reference data to give context
// alongside Linux's own /sys/devices/system/cpu/vulnerabilities/*
// mitigation-status reporting.
func KnownCPUVulnerabilities() []CPUVulnerability {
	return cpuVulns
}

// --- Software intelligence: blacklist/whitelist/CVE reference data ---
// Same honesty caveat as everything else here: this is a small bundled
// SAMPLE dataset (a few dozen entries each), not a live feed and nowhere
// near the scale of a real threat-intel or NVD database. It's useful for
// catching well-known cases (a blacklisted publisher/tool name appearing
// in an installed-package list) but absence from this list means nothing -
// it is NOT evidence of safety.

type BlacklistEntry struct {
	EntityType string `json:"entity_type"` // "publisher" | "software"
	EntityName string `json:"entity_name"`
	Reason     string `json:"reason"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
}

type WhitelistEntry struct {
	EntityType string `json:"entity_type"`
	EntityName string `json:"entity_name"`
	Reason     string `json:"reason"`
	TrustLevel int     `json:"trust_level"`
}

type SoftwareCVE struct {
	CVEID            string  `json:"cve_id"`
	Description      string  `json:"description"`
	CVSSScore        float64 `json:"cvss_score"`
	Severity         string  `json:"severity"`
	AffectedSoftware string  `json:"affected_software"` // JSON array as a string, e.g. ["Google Chrome"]
	ExploitAvailable int     `json:"exploit_available"`
	HasPatch         int     `json:"has_patch"`
}

type SoftwareRef struct {
	Name        string `json:"name"`
	Publisher   string `json:"publisher"`
	Category    string `json:"category"`
	IsLegitimate int   `json:"is_legitimate"`
	RiskScore   int    `json:"risk_score"`
}

var (
	blacklist    []BlacklistEntry
	whitelist    []WhitelistEntry
	softwareCVEs []SoftwareCVE
	softwareRefs []SoftwareRef
)

func init() {
	if b, err := embedded.ReadFile("software_intel.json"); err == nil {
		var doc struct {
			Blacklist []BlacklistEntry `json:"blacklist"`
			Whitelist []WhitelistEntry `json:"whitelist"`
			CVEs      []SoftwareCVE    `json:"cves"`
			Software  []SoftwareRef    `json:"software"`
		}
		if json.Unmarshal(b, &doc) == nil {
			blacklist = doc.Blacklist
			whitelist = doc.Whitelist
			softwareCVEs = doc.CVEs
			softwareRefs = doc.Software
		}
	}
}

// MatchBlacklist returns any bundled blacklist entries whose entity name is
// a case-insensitive substring match (in either direction) of the given
// package/publisher name.
func MatchBlacklist(name string) []BlacklistEntry {
	var out []BlacklistEntry
	lower := strings.ToLower(name)
	for _, b := range blacklist {
		bl := strings.ToLower(b.EntityName)
		if strings.Contains(lower, bl) || strings.Contains(bl, lower) {
			out = append(out, b)
		}
	}
	return out
}

// MatchWhitelist returns any bundled whitelist (trusted publisher) matches.
func MatchWhitelist(name string) []WhitelistEntry {
	var out []WhitelistEntry
	lower := strings.ToLower(name)
	for _, w := range whitelist {
		wl := strings.ToLower(w.EntityName)
		if strings.Contains(lower, wl) || strings.Contains(wl, lower) {
			out = append(out, w)
		}
	}
	return out
}

// MatchSoftwareCVEs returns bundled CVE entries whose affected_software list
// mentions the given name (substring match).
func MatchSoftwareCVEs(name string) []SoftwareCVE {
	var out []SoftwareCVE
	lower := strings.ToLower(name)
	for _, c := range softwareCVEs {
		if strings.Contains(strings.ToLower(c.AffectedSoftware), lower) {
			out = append(out, c)
		}
	}
	return out
}
