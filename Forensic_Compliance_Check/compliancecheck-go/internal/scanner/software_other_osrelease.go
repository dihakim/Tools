//go:build darwin || windows

// internal/scanner/software_other_osrelease.go
//
// macOS: would need `sw_vers` (exec) or reading /System/Library/CoreServices/SystemVersion.plist.
// Windows: would need registry read or `systeminfo` (exec). Neither implemented
// yet - runtime.GOOS/GOARCH from software.go still gets reported either way,
// this only skips the extra human-readable version string.
package scanner

func osReleaseDetail() string {
	return ""
}
