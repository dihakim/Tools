//go:build linux

// internal/scanner/hardware_linux_tpm_secureboot.go
//
// TPM presence: checked via /sys/class/tpm/tpm* existing (the kernel's TPM
// driver exposes a device node there iff a TPM chip is present and the
// driver bound successfully - pure existence check, no ioctl/exec needed).
//
// Secure Boot: checked via the well-known EFI variable
// SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c under
// /sys/firmware/efi/efivars. The value is a small binary blob; the last
// byte is 1 if Secure Boot is enabled, 0 if disabled - this is the same
// thing `mokutil --sb-state` reads, just directly. On a non-UEFI system
// (BIOS/legacy boot, or most VMs/containers) this path won't exist at
// all - that's correctly reported as "not UEFI," not "disabled."
//
// Both were UNTESTABLE for a positive result in this project's sandbox
// (no TPM device node, no /sys/firmware/efi present at all - confirmed by
// direct inspection), so only the graceful "not present" path is verified
// end-to-end. The presence-detection logic itself is straightforward
// existence/byte checks, but flagging that the "TPM found" and "Secure
// Boot enabled" branches specifically have not been run against real
// hardware with those features active.
package scanner

import (
	"os"
	"path/filepath"

	"compliancecheck/internal/model"
)

func scanTPM() []model.Finding {
	entries, err := os.ReadDir("/sys/class/tpm")
	if err != nil {
		f := model.NewFinding(model.CategoryHardware, "tpm_status", "TPM", model.SeverityLow)
		f.Source = "hardware.tpm"
		f.Detail = "No /sys/class/tpm present - no TPM device found (or the driver isn't bound). No hardware-backed key storage/attestation available."
		f.Evidence["present"] = false
		return []model.Finding{f}
	}
	if len(entries) == 0 {
		f := model.NewFinding(model.CategoryHardware, "tpm_status", "TPM", model.SeverityLow)
		f.Source = "hardware.tpm"
		f.Detail = "TPM subsystem present but no TPM device enumerated."
		f.Evidence["present"] = false
		return []model.Finding{f}
	}

	f := model.NewFinding(model.CategoryHardware, "tpm_status", "TPM present", model.SeverityClean)
	f.Source = "hardware.tpm"
	f.Detail = "TPM device found: " + entries[0].Name()
	f.Evidence["present"] = true
	f.Evidence["device"] = entries[0].Name()

	if ver, err := os.ReadFile(filepath.Join("/sys/class/tpm", entries[0].Name(), "tpm_version_major")); err == nil {
		f.Evidence["tpm_version_major"] = string(ver)
	}
	return []model.Finding{f}
}

const secureBootEFIVar = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

func scanSecureBoot() []model.Finding {
	path := filepath.Join("/sys/firmware/efi/efivars", secureBootEFIVar)
	data, err := os.ReadFile(path)
	if err != nil {
		if _, statErr := os.Stat("/sys/firmware/efi"); statErr != nil {
			f := model.NewFinding(model.CategoryHardware, "secure_boot_status", "Secure Boot", model.SeverityInfo)
			f.Source = "hardware.secureboot"
			f.Detail = "System is not booted via UEFI (no /sys/firmware/efi) - Secure Boot doesn't apply (legacy BIOS boot, or a VM/container without UEFI firmware exposed)."
			f.Evidence["uefi"] = false
			return []model.Finding{f}
		}
		f := model.NewFinding(model.CategoryHardware, "secure_boot_status", "Secure Boot", model.SeverityInfo)
		f.Source = "hardware.secureboot"
		f.Detail = "UEFI system, but could not read Secure Boot EFI variable: " + err.Error()
		f.Evidence["uefi"] = true
		return []model.Finding{f}
	}

	// EFI variable format: 4 bytes of attributes, then the value. The
	// SecureBoot variable's value is a single byte: 1 = enabled, 0 = disabled.
	enabled := len(data) > 4 && data[len(data)-1] == 1

	sev := model.SeverityLow
	detail := "Secure Boot is DISABLED - firmware will boot unsigned/untrusted bootloaders and kernels."
	if enabled {
		sev = model.SeverityClean
		detail = "Secure Boot is ENABLED."
	}
	f := model.NewFinding(model.CategoryHardware, "secure_boot_status", "Secure Boot", sev)
	f.Source = "hardware.secureboot"
	f.Detail = detail
	f.Evidence["uefi"] = true
	f.Evidence["enabled"] = enabled
	return []model.Finding{f}
}
