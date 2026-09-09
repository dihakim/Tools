//go:build darwin || windows

// internal/scanner/software_other_packages.go
//
// macOS: `pkgutil --pkgs` + listing /Applications would cover most of it
// (both already-installed, no new install needed). Windows: registry
// Uninstall keys, or `Get-Package`/WMI. Neither implemented yet.
package scanner

import "compliancecheck/internal/model"

func scanSoftwarePackages() []model.Finding {
	f := model.NewFinding(model.CategorySoftware, "packages_not_implemented", "Installed-software inventory not yet implemented on this OS", model.SeverityInfo)
	f.Source = "software.packages"
	f.Detail = "Linux reads dpkg's status file (or rpm -qa) directly; macOS/Windows need a platform-specific implementation not yet built."
	return []model.Finding{f}
}
