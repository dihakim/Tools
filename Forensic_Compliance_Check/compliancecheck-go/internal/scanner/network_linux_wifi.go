//go:build linux

// internal/scanner/network_linux_wifi.go
//
// Reads NetworkManager's saved connection profiles directly from
// /etc/NetworkManager/system-connections/*.nmconnection (plain INI-format
// text files, pure stdlib parsing, no nmcli/exec needed). These files
// typically require root to read (mode 600) - that's not a bug in this
// scanner, it's the OS correctly protecting saved WiFi credentials; running
// without sufficient privilege just means this check reports "permission
// denied" rather than silently fabricating results.
//
// A saved profile with a plaintext PSK is real, meaningful forensic
// signal: it means anyone with access to this file (root, or another tool
// running as root) can read the network's password outright - this is
// exactly what the original spec's network module called out as
// "a significant security vulnerability" when discovered.
//
// UNTESTED against a live NetworkManager setup (this project's sandbox
// has no NetworkManager / no saved connections at all - confirmed by
// direct inspection), so only the graceful "not present" path is verified
// end-to-end. The parsing logic itself is a straightforward INI read, but
// flagging that the "profile found, password extracted" path specifically
// has not been run against real saved connection files.
package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"compliancecheck/internal/model"
)

const nmConnectionsDir = "/etc/NetworkManager/system-connections"

func scanWiFiProfiles() []model.Finding {
	entries, err := os.ReadDir(nmConnectionsDir)
	if err != nil {
		f := model.NewFinding(model.CategoryNetwork, "wifi_profiles_unavailable", "Saved WiFi profiles", model.SeverityInfo)
		f.Source = "network.wifi"
		if os.IsPermission(err) {
			f.Detail = "NetworkManager connection profiles exist but aren't readable without elevated privileges - re-run with root/sudo to inspect saved WiFi credentials."
		} else {
			f.Detail = "No NetworkManager connection profiles found (" + nmConnectionsDir + " not present) - not using NetworkManager, or no saved networks."
		}
		return []model.Finding{f}
	}

	var out []model.Finding
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".nmconnection") {
			continue
		}
		path := filepath.Join(nmConnectionsDir, e.Name())
		profile, err := parseNMConnection(path)
		if err != nil {
			f := model.NewFinding(model.CategoryNetwork, "wifi_profile_unreadable", "Could not read WiFi profile", model.SeverityInfo)
			f.Source = "network.wifi"
			f.Location = path
			f.Detail = err.Error()
			out = append(out, f)
			continue
		}
		if profile.ssid == "" {
			continue // not actually a WiFi profile (could be an Ethernet/VPN connection file)
		}

		sev := model.SeverityClean
		detail := "Saved network \"" + profile.ssid + "\", security: " + orDefault(profile.keyMgmt, "none (open network)")
		if profile.psk != "" {
			sev = model.SeverityMedium
			detail = "Saved network \"" + profile.ssid + "\" has a PLAINTEXT password recoverable from this file (security: " + profile.keyMgmt + ") - anyone who can read this file (root, or another tool running as root) can read the network password outright."
		} else if profile.keyMgmt == "" || strings.EqualFold(profile.keyMgmt, "none") {
			sev = model.SeverityLow
			detail = "Saved network \"" + profile.ssid + "\" is an OPEN network (no authentication)."
		}

		f := model.NewFinding(model.CategoryNetwork, "wifi_profile", "Saved WiFi profile", sev)
		f.Source = "network.wifi"
		f.Location = path
		f.Detail = detail
		f.Evidence["ssid"] = profile.ssid
		f.Evidence["key_mgmt"] = profile.keyMgmt
		f.Evidence["has_plaintext_password"] = profile.psk != ""
		out = append(out, f)
	}

	if out == nil {
		info := model.NewFinding(model.CategoryNetwork, "wifi_profiles_none", "No saved WiFi profiles found", model.SeverityInfo)
		info.Source = "network.wifi"
		out = append(out, info)
	}
	return out
}

type nmProfile struct {
	ssid    string
	keyMgmt string
	psk     string
}

// parseNMConnection is a minimal INI-format reader for exactly the fields
// this scanner needs ([wifi] ssid, [wifi-security] key-mgmt/psk) - not a
// general-purpose INI parser, since NetworkManager's format has quirks
// (hex-escaped SSIDs, etc.) this doesn't attempt to handle exhaustively.
func parseNMConnection(path string) (nmProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nmProfile{}, err
	}
	defer f.Close()

	var profile nmProfile
	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch {
		case section == "wifi" && key == "ssid":
			profile.ssid = val
		case section == "wifi-security" && key == "key-mgmt":
			profile.keyMgmt = val
		case section == "wifi-security" && key == "psk":
			profile.psk = val
		}
	}
	return profile, scanner.Err()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
