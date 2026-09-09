//go:build windows

// internal/webui/browse_windows.go
//
// Windows has no CLI-native file picker, but every Windows install has
// PowerShell, and PowerShell can drive the .NET WinForms file dialogs.
// Shelling out to `powershell.exe` for this is using something already on
// the system, not installing anything new - same principle as using
// `ipconfig` for DNS info or `rundll32` to open a browser.
//
// UNVERIFIED on real Windows (built and tested on Linux, cross-compiled
// for Windows, no Windows machine available to run this against) -
// same honesty caveat as the other Windows-specific code in this project.
package webui

import (
	"os/exec"
	"strings"
)

func browseNative(mode string) ([]string, error) {
	var script string
	if mode == "files" {
		script = `Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.OpenFileDialog
$f.Multiselect = $true
$f.Title = "Select file(s) to scan"
if ($f.ShowDialog() -eq 'OK') { $f.FileNames -join "` + "`n" + `" }`
	} else {
		script = `Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.FolderBrowserDialog
$f.Description = "Select folder to scan"
if ($f.ShowDialog() -eq 'OK') { $f.SelectedPath }`
	}

	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
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
