//go:build linux

// internal/webui/browse_linux.go
//
// Linux has no single universal native file picker the way Windows/macOS
// do - it depends on desktop environment. zenity (GTK, common on
// GNOME/most distros) and kdialog (KDE) cover most desktops without
// requiring anything new to be installed on systems that already have a
// desktop environment. On a minimal server/container with neither (like
// the sandbox this was built in - confirmed neither is present here),
// this returns a clear error so the UI can fall back to manual path entry
// instead of silently failing.
package webui

import (
	"os/exec"
	"strings"
)

func browseNative(mode string) ([]string, error) {
	if path, err := exec.LookPath("zenity"); err == nil {
		return browseZenity(path, mode)
	}
	if path, err := exec.LookPath("kdialog"); err == nil {
		return browseKdialog(path, mode)
	}
	return nil, errNoPickerAvailable
}

var errNoPickerAvailable = &noPickerError{}

type noPickerError struct{}

func (*noPickerError) Error() string {
	return "no native file picker found (tried zenity, kdialog) - type the path manually"
}

func browseZenity(bin, mode string) ([]string, error) {
	var args []string
	if mode == "files" {
		args = []string{"--file-selection", "--multiple", "--separator=\n", "--title=Select file(s) to scan"}
	} else {
		args = []string{"--file-selection", "--directory", "--title=Select folder to scan"}
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		// zenity exits 1 on Cancel - treat as "nothing selected", not an error.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	return splitNonEmptyLines(string(out)), nil
}

func browseKdialog(bin, mode string) ([]string, error) {
	var args []string
	if mode == "files" {
		args = []string{"--getopenfilename", "--multiple", "--separate-output"}
	} else {
		args = []string{"--getexistingdirectory"}
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
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
