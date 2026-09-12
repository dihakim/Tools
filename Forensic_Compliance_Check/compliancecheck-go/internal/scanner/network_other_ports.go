//go:build darwin || windows

// internal/scanner/network_other_ports.go
//
// macOS and Windows don't expose listening sockets through a simple
// readable file the way Linux's /proc/net/tcp does - it requires either
// shelling out to netstat/lsof and parsing locale-dependent text output,
// or platform-specific syscalls (PF_ROUTE sockets on macOS, GetExtendedTcpTable
// on Windows). Rather than ship an unverified text-parser (the DNS resolver
// code took that route for Windows and says so explicitly), this is left
// as an honest gap for now instead of a guess.
package scanner

import "compliancecheck/internal/model"

func scanListeningPorts() []model.Finding {
	f := model.NewFinding(model.CategoryNetwork, "listening_ports_not_implemented", "Listening port enumeration not yet implemented on this OS", model.SeverityInfo)
	f.Source = "network.ports"
	f.Detail = "Linux reads /proc/net/tcp directly; macOS/Windows need a platform-specific implementation not yet built."
	return []model.Finding{f}
}

func scanWiFiProfiles() []model.Finding {
	f := model.NewFinding(model.CategoryNetwork, "wifi_profiles_not_implemented", "Saved WiFi profile extraction not yet implemented on this OS", model.SeverityInfo)
	f.Source = "network.wifi"
	f.Detail = "Linux reads NetworkManager's connection files directly. macOS keeps WiFi passwords in the Keychain (needs `security find-generic-password` or Keychain Services API - not yet built). Windows keeps them in the WLAN AutoConfig store (needs `netsh wlan show profile key=clear`, which requires admin and is per-profile - not yet built)."
	return []model.Finding{f}
}
