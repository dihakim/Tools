//go:build linux

// internal/scanner/hardware_linux_pci.go
//
// Enumerates PCI devices (GPUs, network adapters, controllers, etc.) via
// /sys/bus/pci/devices - pure stdlib file reads, no lspci/exec needed.
// Cross-references vendor/device IDs against the offline PCI registry
// (internal/hwintel) for human-readable names, since the kernel itself
// only exposes raw hex IDs.
package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"compliancecheck/internal/hwintel"
	"compliancecheck/internal/model"
)

func scanPCI() []model.Finding {
	root := "/sys/bus/pci/devices"
	entries, err := os.ReadDir(root)
	if err != nil {
		return []model.Finding{unreadableHW("pci", err)}
	}

	var out []model.Finding
	for _, e := range entries {
		devPath := filepath.Join(root, e.Name())
		vendorID := strings.TrimPrefix(readSysAttr(filepath.Join(devPath, "vendor")), "0x")
		deviceID := strings.TrimPrefix(readSysAttr(filepath.Join(devPath, "device")), "0x")
		if vendorID == "" || deviceID == "" {
			continue
		}

		label := "vendor:" + vendorID + " device:" + deviceID
		deviceClass := ""
		if reg, ok := hwintel.LookupPCIDevice(vendorID, deviceID); ok {
			label = strings.TrimSpace(reg.VendorNameOr(vendorID) + " " + reg.DeviceNameOr(deviceID))
			deviceClass = reg.DeviceClass
		}

		f := model.NewFinding(model.CategoryHardware, "pci_device", "PCI device", model.SeverityClean)
		f.Source = "hardware.pci"
		f.Location = e.Name()
		f.Detail = label
		f.Evidence["vendor_id"] = vendorID
		f.Evidence["device_id"] = deviceID
		if deviceClass != "" {
			f.Evidence["device_class"] = deviceClass
		}
		out = append(out, f)
	}
	if out == nil {
		info := model.NewFinding(model.CategoryHardware, "pci_none", "No PCI devices found", model.SeverityInfo)
		info.Source = "hardware.pci"
		out = append(out, info)
	}
	return out
}
