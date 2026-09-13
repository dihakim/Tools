//go:build windows

// internal/scanner/storage_windows_suid.go
//
// Windows has no SUID/SGID concept (its privilege model is entirely
// different - tokens, UAC, service accounts) - this check genuinely
// doesn't apply here, not just "not implemented yet."
package scanner

import "compliancecheck/internal/model"

func scanSUIDFiles() []model.Finding {
	f := model.NewFinding(model.CategoryStorage, "suid_not_applicable", "SUID/SGID scanning does not apply on Windows", model.SeverityInfo)
	f.Source = "storage.suid"
	f.Detail = "Windows has no SUID/SGID concept - its privilege elevation model (UAC, service accounts, access tokens) is entirely different."
	return []model.Finding{f}
}
