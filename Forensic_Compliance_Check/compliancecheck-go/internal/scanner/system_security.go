// internal/scanner/system_security.go
//
// Orchestrates security checks that scan well-known, fixed system
// locations rather than a user-specified --target - same pattern as
// NetworkScanner/SoftwareScanner/HardwareScanner (no target needed).
// Findings land in whichever category best fits the specific check
// (mostly Storage, since these mostly examine specific files).
package scanner

import "compliancecheck/internal/model"

type SystemSecurityScanner struct{}

func NewSystemSecurityScanner() *SystemSecurityScanner {
	return &SystemSecurityScanner{}
}

func (s *SystemSecurityScanner) Scan() []model.Finding {
	var out []model.Finding
	out = append(out, scanSSHSecurity()...)
	out = append(out, scanSUIDFiles()...)      // OS-specific, see storage_*_suid.go
	out = append(out, scanCredentialFiles()...) // OS-specific paths, see storage_*_secrets.go
	return out
}
