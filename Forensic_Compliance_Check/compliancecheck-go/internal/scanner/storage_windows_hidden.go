//go:build windows

// internal/scanner/storage_windows_hidden.go
//
// Windows hidden-file attribute (distinct from the Unix dot-prefix
// convention - a Windows file can be hidden regardless of its name).
package scanner

import (
	"syscall"
)

func isHiddenPath(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return attrs&syscall.FILE_ATTRIBUTE_HIDDEN != 0
}
