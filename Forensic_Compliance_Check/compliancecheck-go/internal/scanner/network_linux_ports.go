//go:build linux

// internal/scanner/network_linux_ports.go
//
// Enumerates listening TCP ports by reading /proc/net/tcp and /proc/net/tcp6
// directly - no exec, no external tool (netstat/ss may not even be
// installed on a minimal container), just the kernel's own table. This is
// the most "no install required" approach available and it's exact, not
// a text-parsing guess.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"compliancecheck/internal/model"
	"compliancecheck/internal/netinfo"
)

// TCP_LISTEN state code in /proc/net/tcp's "st" column.
const tcpListenState = "0A"

func scanListeningPorts() []model.Finding {
	var out []model.Finding
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		entries, err := parseProcNetTCP(path)
		if err != nil {
			continue // best-effort: e.g. IPv6 disabled, tcp6 won't exist
		}
		for _, e := range entries {
			if e.state != tcpListenState {
				continue
			}
			f := model.NewFinding(model.CategoryNetwork, "listening_port", "Listening TCP port", model.SeverityInfo)
			f.Source = "network.ports"
			f.Location = fmt.Sprintf("%s:%d", e.localAddr, e.localPort)
			f.Detail = fmt.Sprintf("Listening on port %d (%s), owned by uid %d", e.localPort, addrScope(e.localAddr), e.uid)
			f.Evidence["port"] = e.localPort
			f.Evidence["address"] = e.localAddr
			f.Evidence["address_classification"] = netinfo.Classify(e.localAddr)
			f.Evidence["uid"] = e.uid
			f.Evidence["source_table"] = path
			out = append(out, f)
		}
	}
	if out == nil {
		info := model.NewFinding(model.CategoryNetwork, "listening_ports_unavailable", "Could not enumerate listening ports", model.SeverityInfo)
		info.Source = "network.ports"
		info.Detail = "/proc/net/tcp and /proc/net/tcp6 were both unreadable."
		return []model.Finding{info}
	}
	return out
}

func addrScope(ip string) string {
	if ip == "0.0.0.0" || ip == "::" {
		return "all interfaces"
	}
	if ip == "127.0.0.1" || ip == "::1" {
		return "localhost only"
	}
	return ip
}

type tcpEntry struct {
	localAddr string
	localPort int
	state     string
	uid       int
}

func parseProcNetTCP(path string) ([]tcpEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []tcpEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first { // header line
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		addr, port, err := decodeHexAddrPort(fields[1])
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(fields[7])
		entries = append(entries, tcpEntry{
			localAddr: addr,
			localPort: port,
			state:     fields[3],
			uid:       uid,
		})
	}
	return entries, nil
}

// decodeHexAddrPort decodes /proc/net/tcp's "ADDR:PORT" hex format, e.g.
// "0100007F:1F90" (little-endian hex IPv4) -> "127.0.0.1", 8080.
func decodeHexAddrPort(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad addr:port %q", s)
	}
	port64, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}

	hexAddr := parts[0]
	var ip string
	switch len(hexAddr) {
	case 8: // IPv4: 4 bytes, little-endian per 32-bit word
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0, err
			}
			b[3-i] = byte(v)
		}
		ip = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 32: // IPv6: 16 bytes, little-endian per 32-bit word
		b := make([]byte, 16)
		for w := 0; w < 4; w++ {
			word := hexAddr[w*8 : w*8+8]
			for i := 0; i < 4; i++ {
				v, err := strconv.ParseUint(word[i*2:i*2+2], 16, 8)
				if err != nil {
					return "", 0, err
				}
				b[w*4+(3-i)] = byte(v)
			}
		}
		ip = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3]),
			uint16(b[4])<<8|uint16(b[5]), uint16(b[6])<<8|uint16(b[7]),
			uint16(b[8])<<8|uint16(b[9]), uint16(b[10])<<8|uint16(b[11]),
			uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
	default:
		return "", 0, fmt.Errorf("unexpected addr hex length %d", len(hexAddr))
	}
	return ip, int(port64), nil
}
