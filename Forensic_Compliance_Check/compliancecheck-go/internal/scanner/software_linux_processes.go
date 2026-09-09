//go:build linux

// internal/scanner/software_linux_processes.go
//
// Reads /proc/<pid>/{comm,cmdline,status} directly - no exec, no `ps`
// dependency (which may not even be installed on a minimal container).
// Flags a couple of well-known suspicious patterns: a process whose
// binary has been deleted from disk while still running (classic
// fileless-persistence/cleanup-after-execution pattern), and processes
// running as root with no associated executable path resolvable.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"compliancecheck/internal/model"
)

const maxProcessFindings = 500 // cap so a busy system doesn't produce an unreadable report

func scanProcesses() []model.Finding {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		info := model.NewFinding(model.CategorySoftware, "processes_unreadable", "Could not enumerate running processes", model.SeverityInfo)
		info.Source = "software.processes"
		info.Detail = err.Error()
		return []model.Finding{info}
	}

	var out []model.Finding
	for _, e := range entries {
		if len(out) >= maxProcessFindings {
			break
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		f, ok := processFinding(pid)
		if ok {
			out = append(out, f)
		}
	}
	if out == nil {
		info := model.NewFinding(model.CategorySoftware, "processes_none", "No processes could be read", model.SeverityInfo)
		info.Source = "software.processes"
		out = append(out, info)
	}
	return out
}

func processFinding(pid int) (model.Finding, bool) {
	base := fmt.Sprintf("/proc/%d", pid)

	comm := readFirstLine(base + "/comm")
	if comm == "" {
		return model.Finding{}, false // process exited between readdir and read, or unreadable
	}

	cmdlineRaw, _ := os.ReadFile(base + "/cmdline")
	cmdline := strings.ReplaceAll(strings.TrimRight(string(cmdlineRaw), "\x00"), "\x00", " ")

	exePath, exeErr := os.Readlink(base + "/exe")
	deleted := exeErr == nil && strings.Contains(exePath, "(deleted)")

	uid := -1
	if status, err := os.ReadFile(base + "/status"); err == nil {
		uid = parseUIDFromStatus(string(status))
	}

	sev := model.SeverityClean
	var note string
	if deleted {
		sev = model.SeverityMedium
		note = "process is running from a deleted/replaced binary on disk (" + exePath + ") - common after self-cleanup or fileless-persistence techniques"
	} else if uid == 0 && exeErr != nil && cmdline != "" {
		// Kernel threads (kworker, ksoftirqd, etc.) always have an empty cmdline
		// and no /proc/pid/exe target - that's normal, not suspicious. Only flag
		// an unresolvable exe when there IS a real command line, meaning this is
		// an actual userspace process running as root that we can't verify.
		sev = model.SeverityLow
		note = "running as root with an unresolvable executable path despite having a command line - worth a closer look"
	}

	f := model.NewFinding(model.CategorySoftware, "process", "Running process", sev)
	f.Source = "software.processes"
	f.Location = comm
	if note != "" {
		f.Detail = note
	} else {
		f.Detail = "pid=" + strconv.Itoa(pid)
	}
	f.Evidence["pid"] = pid
	f.Evidence["comm"] = comm
	if cmdline != "" {
		f.Evidence["cmdline"] = cmdline
	}
	if exeErr == nil {
		f.Evidence["exe"] = exePath
	}
	if uid >= 0 {
		f.Evidence["uid"] = uid
	}
	return f, true
}

func readFirstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func parseUIDFromStatus(status string) int {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, err := strconv.Atoi(fields[1])
				if err == nil {
					return uid
				}
			}
		}
	}
	return -1
}
