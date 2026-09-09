// internal/scanner/hardware.go
//
// Hardware category. Scoped for this pass to what's readable without any
// external tool: CPU, memory, storage/mounts, USB devices, and a basic
// disk-encryption presence check. The Python version's much larger surface
// (BIOS/TPM/secure boot/firmware integrity/temperatures/fan speeds/
// benchmarking) needs either vendor tools (dmidecode, smartctl - an install
// requirement we're trying to avoid) or platform-specific APIs not yet
// built - see README for the honest list of what's left.
package scanner

import "compliancecheck/internal/model"

type HardwareScanner struct{}

func NewHardwareScanner() *HardwareScanner {
	return &HardwareScanner{}
}

func (s *HardwareScanner) Scan() []model.Finding {
	var out []model.Finding
	out = append(out, scanCPU()...)
	out = append(out, scanMemory()...)
	out = append(out, scanStorage()...)
	out = append(out, scanUSB()...)
	out = append(out, scanDiskEncryption()...)
	return out
}
