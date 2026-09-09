//go:build darwin

// internal/webui/browse_darwin.go
//
// macOS ships `osascript` (AppleScript/JXA runner) on every install -
// using it to drive the native Finder file/folder picker is, again, using
// something already there rather than installing anything.
//
// UNVERIFIED on a real Mac (no Mac available to test against, same
// honesty caveat as the rest of this project's untested OS-specific code).
package webui

import (
	"os/exec"
	"strings"
)

func browseNative(mode string) ([]string, error) {
	var script string
	if mode == "files" {
		script = `set theFiles to choose file with prompt "Select file(s) to scan" with multiple selections allowed
set out to ""
repeat with f in theFiles
	set out to out & POSIX path of f & linefeed
end repeat
return out`
	} else {
		script = `set theFolder to choose folder with prompt "Select folder to scan"
return POSIX path of theFolder`
	}

	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		// User cancelling the dialog also exits non-zero on macOS - treat that
		// as "nothing selected" rather than a hard error where possible.
		if strings.Contains(err.Error(), "exit status 1") {
			return nil, nil
		}
		return nil, err
	}
	return splitNonEmptyLines(string(out)), nil
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
