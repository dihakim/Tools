//go:build windows

// internal/scanner/software_windows_users.go
//
// Windows local accounts live in the SAM, not a readable text file -
// needs either `net user` (exec, locale-dependent parsing) or the
// NetUserEnum Win32 API (requires a syscall wrapper this pass doesn't
// include). Left as an honest gap rather than a guess.
package scanner

import "compliancecheck/internal/model"

func scanUsers() []model.Finding {
	f := model.NewFinding(model.CategorySoftware, "users_not_implemented", "Local account enumeration not yet implemented on Windows", model.SeverityInfo)
	f.Source = "software.users"
	f.Detail = "Needs NetUserEnum (Win32 API) or `net user` output parsing - not yet built."
	return []model.Finding{f}
}
