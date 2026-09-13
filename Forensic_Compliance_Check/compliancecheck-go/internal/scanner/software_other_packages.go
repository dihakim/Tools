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

func scanPersistence() []model.Finding {
	f := model.NewFinding(model.CategorySoftware, "persistence_not_implemented", "Persistence/autostart scanning not yet implemented on this OS", model.SeverityInfo)
	f.Source = "software.persistence"
	f.Detail = "Linux reads cron/systemd/XDG-autostart files directly. macOS needs launchd plist scanning (~/Library/LaunchAgents, /Library/Launch{Agents,Daemons}). Windows needs the Run/RunOnce registry keys and the Startup folder. Neither implemented yet."
	return []model.Finding{f}
}
