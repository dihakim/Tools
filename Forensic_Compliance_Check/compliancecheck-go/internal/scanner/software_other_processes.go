//go:build darwin || windows

// internal/scanner/software_other_processes.go
//
// macOS: needs sysctl(KERN_PROC) or `ps`/`lsof` exec. Windows: needs
// CreateToolhelp32Snapshot or `tasklist` exec. Neither implemented yet.
package scanner

import "compliancecheck/internal/model"

func scanProcesses() []model.Finding {
	f := model.NewFinding(model.CategorySoftware, "processes_not_implemented", "Process enumeration not yet implemented on this OS", model.SeverityInfo)
	f.Source = "software.processes"
	f.Detail = "Linux reads /proc directly; macOS/Windows need a platform-specific implementation not yet built."
	return []model.Finding{f}
}
