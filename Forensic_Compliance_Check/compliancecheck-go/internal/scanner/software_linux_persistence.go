//go:build linux

// internal/scanner/software_linux_persistence.go
//
// Enumerates the standard Linux persistence/autostart mechanisms - the
// same places malware persistence and legitimate scheduled-task auditing
// both look. Every source here is a pure file read; the systemd
// enabled-units check specifically reads the /etc/systemd/system/*.wants/
// symlinks directly rather than shelling out to `systemctl`, which
// requires a running systemd bus connection that isn't guaranteed
// available (confirmed in this project's own sandbox: `systemctl
// list-timers` failed with "Failed to connect to bus" while the same
// information was still readable directly from disk).
//
// This reports every persistence entry found for manual review (not just
// "suspicious" ones) - CLEAN severity by default, since cron jobs and
// enabled services are completely normal; the value here is
// completeness/visibility, not a suspicious/clean judgment call this
// tool isn't positioned to make about arbitrary command lines.
package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"compliancecheck/internal/model"
)

func scanPersistence() []model.Finding {
	var out []model.Finding
	out = append(out, scanCronEntries()...)
	out = append(out, scanSystemdEnabledUnits()...)
	out = append(out, scanAutostartDesktopEntries()...)
	out = append(out, scanRCLocal()...)
	if out == nil {
		f := model.NewFinding(model.CategorySoftware, "persistence_none", "No persistence/autostart entries found", model.SeverityInfo)
		f.Source = "software.persistence"
		out = append(out, f)
	}
	return out
}

func scanCronEntries() []model.Finding {
	var out []model.Finding

	paths := []string{"/etc/crontab"}
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			paths = append(paths, filepath.Join("/etc/cron.d", e.Name()))
		}
	}
	for _, p := range paths {
		out = append(out, parseCrontabFile(p)...)
	}

	// Periodic script directories - just list what's there, not their content.
	for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			f := model.NewFinding(model.CategorySoftware, "persistence_cron_periodic", "Scheduled script ("+filepath.Base(dir)+")", model.SeverityClean)
			f.Source = "software.persistence"
			f.Location = filepath.Join(dir, e.Name())
			f.Detail = "Runs " + strings.TrimPrefix(filepath.Base(dir), "cron.")
			out = append(out, f)
		}
	}

	// Per-user crontabs typically require root to read (mode 600, root-owned
	// dir) - report the gap honestly rather than silently skipping it.
	if _, err := os.ReadDir("/var/spool/cron/crontabs"); err != nil {
		f := model.NewFinding(model.CategorySoftware, "persistence_user_crontabs_unavailable", "Per-user crontabs", model.SeverityInfo)
		f.Source = "software.persistence"
		f.Detail = "Could not read /var/spool/cron/crontabs (" + err.Error() + ") - typically needs root."
		out = append(out, f)
	}

	return out
}

func parseCrontabFile(path string) []model.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []model.Finding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		finding := model.NewFinding(model.CategorySoftware, "persistence_cron_entry", "Cron job", model.SeverityClean)
		finding.Source = "software.persistence"
		finding.Location = path
		finding.Detail = line
		finding.Evidence["schedule"] = strings.Join(fields[0:5], " ")
		out = append(out, finding)
	}
	return out
}

func scanSystemdEnabledUnits() []model.Finding {
	var out []model.Finding
	wantsDirs, err := filepath.Glob("/etc/systemd/system/*.wants")
	if err != nil || len(wantsDirs) == 0 {
		f := model.NewFinding(model.CategorySoftware, "persistence_systemd_unavailable", "Systemd enabled units", model.SeverityInfo)
		f.Source = "software.persistence"
		f.Detail = "No /etc/systemd/system/*.wants directories found - not using systemd, or nothing locally enabled."
		return []model.Finding{f}
	}

	for _, dir := range wantsDirs {
		target := strings.TrimSuffix(filepath.Base(dir), ".wants")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			f := model.NewFinding(model.CategorySoftware, "persistence_systemd_unit", "Enabled systemd unit", model.SeverityClean)
			f.Source = "software.persistence"
			f.Location = filepath.Join(dir, e.Name())
			f.Detail = e.Name() + " enabled for " + target
			if resolved, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil {
				f.Evidence["unit_file"] = resolved
			}
			out = append(out, f)
		}
	}
	return out
}

func scanAutostartDesktopEntries() []model.Finding {
	var out []model.Finding
	dirs := []string{"/etc/xdg/autostart"}
	if home := homeDir(); home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", "autostart"))
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			exec := readDesktopExecLine(path)
			f := model.NewFinding(model.CategorySoftware, "persistence_autostart", "Autostart application", model.SeverityClean)
			f.Source = "software.persistence"
			f.Location = path
			f.Detail = exec
			out = append(out, f)
		}
	}
	return out
}

func readDesktopExecLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Exec=") {
			return strings.TrimPrefix(line, "Exec=")
		}
	}
	return ""
}

func scanRCLocal() []model.Finding {
	data, err := os.ReadFile("/etc/rc.local")
	if err != nil {
		return nil
	}
	f := model.NewFinding(model.CategorySoftware, "persistence_rc_local", "/etc/rc.local present", model.SeverityLow)
	f.Source = "software.persistence"
	f.Location = "/etc/rc.local"
	f.Detail = "rc.local runs at boot with root privileges - worth reviewing its contents directly."
	f.Evidence["size_bytes"] = len(data)
	return []model.Finding{f}
}
