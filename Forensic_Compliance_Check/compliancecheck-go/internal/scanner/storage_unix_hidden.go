//go:build linux || darwin

// internal/scanner/storage_unix_hidden.go
//
// Unix hidden-file convention: filename starts with "." - extremely
// common and mostly benign (.gitignore, .bashrc, .env), but worth
// surfacing for visibility per the original spec's "identifies
// suspicious directory hierarchies, hidden directories" framing. LOW
// severity, not alarming - the value here is completeness, not a
// suspicious/clean judgment about any specific dotfile.
package scanner

import "path/filepath"

func isHiddenPath(path string) bool {
	base := filepath.Base(path)
	return len(base) > 1 && base[0] == '.'
}
