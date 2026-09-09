//go:build linux

// internal/scanner/hardware_linux_encryption.go
//
// Heuristic, not authoritative: a mounted root/home filesystem backed by a
// /dev/mapper/* device is consistent with LUKS full-disk encryption, and a
// non-empty /etc/crypttab confirms crypt mappings are configured. This
// can't distinguish LUKS from plain unencrypted LVM without deeper
// cryptsetup queries, so a positive signal here is a good sign but a
// negative one (no dm-crypt detected) is what actually matters for
// compliance review - flagged for a human to confirm, not asserted as fact.
package scanner

import (
	"os"
	"strings"

	"compliancecheck/internal/model"
)

func scanDiskEncryption() []model.Finding {
	rootEncrypted := false
	if mounts, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(mounts), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			device, mountpoint := fields[0], fields[1]
			if mountpoint == "/" && strings.Contains(device, "/dev/mapper/") {
				rootEncrypted = true
			}
		}
	}

	crypttabConfigured := false
	if data, err := os.ReadFile("/etc/crypttab"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				crypttabConfigured = true
				break
			}
		}
	}

	sev := model.SeverityClean
	detail := "Root filesystem appears to be on an encrypted (device-mapper) volume."
	if !rootEncrypted {
		sev = model.SeverityLow
		detail = "Root filesystem does not appear to be on a device-mapper/LUKS volume - full-disk encryption may not be enabled. This is a heuristic; confirm with `cryptsetup status` / `lsblk -f` before concluding the disk is unencrypted."
	}

	f := model.NewFinding(model.CategoryHardware, "disk_encryption", "Disk encryption (heuristic)", sev)
	f.Source = "hardware.encryption"
	f.Detail = detail
	f.Evidence["root_on_device_mapper"] = rootEncrypted
	f.Evidence["crypttab_configured"] = crypttabConfigured
	return []model.Finding{f}
}
