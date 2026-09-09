// internal/scanner/software.go
//
// Software category. Scoped for this pass to: OS identity, local user
// accounts (the "who else uses this device" part of the original ask),
// and running processes. Installed-package inventory is not yet ported -
// see README.
package scanner

import (
	"os"
	"runtime"

	"compliancecheck/internal/model"
)

type SoftwareScanner struct{}

func NewSoftwareScanner() *SoftwareScanner {
	return &SoftwareScanner{}
}

func (s *SoftwareScanner) Scan() []model.Finding {
	var out []model.Finding
	out = append(out, scanOSInfo())
	out = append(out, scanUsers()...)   // OS-specific, see software_*.go
	out = append(out, scanProcesses()...) // OS-specific, see software_*.go
	out = append(out, scanSoftwarePackages()...) // OS-specific, see software_*_packages.go
	return out
}

func scanOSInfo() model.Finding {
	hostname, _ := os.Hostname()
	f := model.NewFinding(model.CategorySoftware, "os_identity", "Operating system", model.SeverityInfo)
	f.Source = "software.os"
	f.Detail = runtime.GOOS + "/" + runtime.GOARCH + " on host " + hostname
	f.Evidence["os"] = runtime.GOOS
	f.Evidence["arch"] = runtime.GOARCH
	f.Evidence["hostname"] = hostname
	f.Evidence["num_cpu"] = runtime.NumCPU()
	if release := osReleaseDetail(); release != "" {
		f.Evidence["release_info"] = release
		f.Detail += " (" + release + ")"
	}
	return f
}
