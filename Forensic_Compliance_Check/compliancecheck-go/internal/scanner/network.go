// internal/scanner/network.go
//
// Network category scanner. Interfaces and the hosts file are handled here
// with pure stdlib and work identically on every OS. DNS resolver config
// and listening-port enumeration are OS-specific (see network_linux.go /
// network_unix.go / network_windows.go) because there's no cross-platform
// stdlib API for either - each OS-specific file is honest in its own
// comments about what's tested vs. best-effort.
package scanner

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"

	"compliancecheck/internal/model"
	"compliancecheck/internal/netinfo"
)

type NetworkScanner struct{}

func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{}
}

func (s *NetworkScanner) Scan() []model.Finding {
	var out []model.Finding
	out = append(out, scanInterfaces()...)
	out = append(out, scanHostsFile()...)
	out = append(out, scanDNSResolvers()...) // OS-specific, see network_*.go
	out = append(out, scanListeningPorts()...) // OS-specific, see network_*.go
	return out
}

func scanInterfaces() []model.Finding {
	var out []model.Finding
	ifaces, err := net.Interfaces()
	if err != nil {
		f := model.NewFinding(model.CategoryNetwork, "interface_enum_error", "Could not enumerate network interfaces", model.SeverityInfo)
		f.Source = "network.interfaces"
		f.Detail = err.Error()
		return []model.Finding{f}
	}

	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		var addrStrs []string
		var addrClasses []netinfo.IPClass
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
			addrClasses = append(addrClasses, netinfo.Classify(stripCIDR(a.String())))
		}

		up := iface.Flags&net.FlagUp != 0
		loopback := iface.Flags&net.FlagLoopback != 0

		sev := model.SeverityClean
		title := "Network interface"
		if up && !loopback && len(addrStrs) == 0 {
			// Up with no address is mildly unusual (link-local only, or mid-DHCP) -
			// worth a look, not an alarm.
			sev = model.SeverityInfo
		}

		f := model.NewFinding(model.CategoryNetwork, "interface", title, sev)
		f.Source = "network.interfaces"
		f.Location = iface.Name
		f.Detail = ifaceSummary(iface, up, loopback, addrStrs)
		f.Evidence["mac"] = iface.HardwareAddr.String()
		f.Evidence["addresses"] = addrStrs
		f.Evidence["address_classification"] = addrClasses
		f.Evidence["up"] = up
		f.Evidence["loopback"] = loopback
		f.Evidence["mtu"] = iface.MTU
		out = append(out, f)
	}
	return out
}

// stripCIDR turns "192.168.1.5/24" or "fe80::1/64" into just the IP part.
func stripCIDR(addr string) string {
	if i := strings.Index(addr, "/"); i != -1 {
		return addr[:i]
	}
	return addr
}

func ifaceSummary(iface net.Interface, up, loopback bool, addrs []string) string {
	state := "down"
	if up {
		state = "up"
	}
	kind := "interface"
	if loopback {
		kind = "loopback interface"
	}
	if len(addrs) == 0 {
		return kind + " (" + state + "), no addresses assigned"
	}
	return kind + " (" + state + "): " + strings.Join(addrs, ", ")
}

func hostsFilePath() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return root + `\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// scanHostsFile surfaces every active mapping for manual review, and flags
// (LOW, not higher - hosts-file ad/tracker blocking is extremely common and
// benign) any entry that blackholes what looks like a real external domain,
// since that's also exactly how DNS-hijacking malware and some parental-
// control/monitoring tools work.
func scanHostsFile() []model.Finding {
	path := hostsFilePath()
	f, err := os.Open(path)
	if err != nil {
		info := model.NewFinding(model.CategoryNetwork, "hosts_file_unreadable", "Could not read hosts file", model.SeverityInfo)
		info.Source = "network.hosts"
		info.Location = path
		info.Detail = err.Error()
		return []model.Finding{info}
	}
	defer f.Close()

	var out []model.Finding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		for _, domain := range fields[1:] {
			domain = strings.TrimSpace(domain)
			if domain == "" || strings.HasPrefix(domain, "#") {
				break
			}
			sev := model.SeverityClean
			class := netinfo.Classify(ip)
			if looksLikeRealDomain(domain) && class.Valid && (class.Scope == "loopback" || class.Scope == "unspecified") {
				sev = model.SeverityLow
			}
			finding := model.NewFinding(model.CategoryNetwork, "hosts_entry", "Hosts file entry", sev)
			finding.Source = "network.hosts"
			finding.Location = path
			finding.Detail = domain + " -> " + ip
			finding.Evidence["ip"] = ip
			finding.Evidence["domain"] = domain
			finding.Evidence["ip_classification"] = class
			out = append(out, finding)
		}
	}
	if len(out) == 0 {
		clean := model.NewFinding(model.CategoryNetwork, "hosts_file_default", "Hosts file has no custom entries", model.SeverityClean)
		clean.Source = "network.hosts"
		clean.Location = path
		out = append(out, clean)
	}
	return out
}

func looksLikeRealDomain(d string) bool {
	d = strings.ToLower(d)
	if d == "localhost" || strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".test") ||
		strings.HasSuffix(d, ".dev") || strings.HasSuffix(d, ".internal") {
		return false
	}
	return strings.Contains(d, ".")
}
