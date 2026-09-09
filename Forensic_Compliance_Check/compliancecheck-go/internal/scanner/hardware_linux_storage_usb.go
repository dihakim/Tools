//go:build linux

// internal/scanner/hardware_linux_storage_usb.go
package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"compliancecheck/internal/model"
)

// pseudo/virtual filesystems that aren't "storage" in any meaningful sense -
// skipped so the report isn't dominated by cgroup/proc/sys/tmpfs noise.
var skipFSTypes = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true,
	"cgroup": true, "cgroup2": true, "pstore": true, "bpf": true, "tracefs": true,
	"debugfs": true, "mqueue": true, "hugetlbfs": true, "securityfs": true,
	"autofs": true, "overlay": true, "squashfs": true, "nsfs": true, "binfmt_misc": true,
}

func scanStorage() []model.Finding {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return []model.Finding{unreadableHW("storage", err)}
	}
	defer f.Close()

	var out []model.Finding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		device, mountpoint, fstype := fields[0], fields[1], fields[2]
		if skipFSTypes[fstype] || !strings.HasPrefix(device, "/dev/") {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			continue
		}
		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeBytes := stat.Bavail * uint64(stat.Bsize)
		usedPct := 0.0
		if totalBytes > 0 {
			usedPct = 100 * (1 - float64(freeBytes)/float64(totalBytes))
		}

		sev := model.SeverityClean
		var note string
		if usedPct >= 95 {
			sev = model.SeverityLow
			note = "disk is nearly full (" + strconv.FormatFloat(usedPct, 'f', 1, 64) + "% used) - not a security finding, but worth knowing"
		}

		finding := model.NewFinding(model.CategoryHardware, "storage_volume", "Storage volume", sev)
		finding.Source = "hardware.storage"
		finding.Location = mountpoint
		if note != "" {
			finding.Detail = note
		} else {
			finding.Detail = device + " (" + fstype + "), " + strconv.FormatFloat(usedPct, 'f', 1, 64) + "% used"
		}
		finding.Evidence["device"] = device
		finding.Evidence["fstype"] = fstype
		finding.Evidence["total_bytes"] = totalBytes
		finding.Evidence["free_bytes"] = freeBytes
		finding.Evidence["used_percent"] = usedPct
		out = append(out, finding)
	}
	return out
}

func scanUSB() []model.Finding {
	root := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(root)
	if err != nil {
		return []model.Finding{unreadableHW("usb", err)}
	}

	var out []model.Finding
	for _, e := range entries {
		name := e.Name()
		// Only report actual devices (numeric or "N-N" bus-port names), skip
		// interface entries like "1-1:1.0" which are sub-nodes of a device.
		if strings.Contains(name, ":") {
			continue
		}
		devPath := filepath.Join(root, name)
		vendor := readSysAttr(filepath.Join(devPath, "idVendor"))
		product := readSysAttr(filepath.Join(devPath, "idProduct"))
		manufacturer := readSysAttr(filepath.Join(devPath, "manufacturer"))
		productName := readSysAttr(filepath.Join(devPath, "product"))
		serial := readSysAttr(filepath.Join(devPath, "serial"))

		if vendor == "" && product == "" {
			continue // not a real device node
		}

		finding := model.NewFinding(model.CategoryHardware, "usb_device", "USB device", model.SeverityClean)
		finding.Source = "hardware.usb"
		finding.Location = name
		label := strings.TrimSpace(manufacturer + " " + productName)
		if label == "" {
			label = "vendor:" + vendor + " product:" + product
		}
		finding.Detail = label
		finding.Evidence["id_vendor"] = vendor
		finding.Evidence["id_product"] = product
		finding.Evidence["manufacturer"] = manufacturer
		finding.Evidence["product"] = productName
		if serial != "" {
			finding.Evidence["serial"] = serial
		}
		out = append(out, finding)
	}
	if out == nil {
		info := model.NewFinding(model.CategoryHardware, "usb_none", "No USB devices found", model.SeverityInfo)
		info.Source = "hardware.usb"
		out = append(out, info)
	}
	return out
}

func readSysAttr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
