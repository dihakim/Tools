//go:build darwin || windows

// internal/scanner/hardware_other.go
//
// macOS: CPU/memory/storage/USB all need `sysctl`/`system_profiler`/`ioreg`
// (exec) or IOKit APIs. Windows: needs WMI or registry queries. Neither
// implemented yet - honest gap rather than a guess, matching the same
// approach taken for network ports and process enumeration on these OSes.
package scanner

import "compliancecheck/internal/model"

func scanCPU() []model.Finding             { return []model.Finding{hwNotImplemented("cpu")} }
func scanMemory() []model.Finding          { return []model.Finding{hwNotImplemented("memory")} }
func scanStorage() []model.Finding         { return []model.Finding{hwNotImplemented("storage")} }
func scanUSB() []model.Finding             { return []model.Finding{hwNotImplemented("usb")} }
func scanDiskEncryption() []model.Finding  { return []model.Finding{hwNotImplemented("disk_encryption")} }

func hwNotImplemented(what string) model.Finding {
	f := model.NewFinding(model.CategoryHardware, what+"_not_implemented", "Hardware "+what+" scan not yet implemented on this OS", model.SeverityInfo)
	f.Source = "hardware." + what
	f.Detail = "Linux reads /proc and /sys directly; macOS/Windows need a platform-specific implementation not yet built."
	return f
}
