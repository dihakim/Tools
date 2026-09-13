//go:build linux || darwin

// internal/scanner/storage_unix_suid.go
//
// Classic Unix hardening check (same one Lynis/CIS benchmarks perform):
// enumerate SUID/SGID binaries (a SUID binary runs with its owner's
// privileges regardless of who executes it - a small, well-known set is
// normal on any system, e.g. passwd/sudo/ping; an unexpected one is a
// common privilege-escalation backdoor technique).
//
// Deliberately bounded to a fixed list of common system binary
// directories rather than a whole-filesystem walk - a full recursive
// walk from / would be slow and mostly noise (most of a filesystem isn't
// security-relevant for this check); this mirrors what real hardening
// scanners check by default.
package scanner

import (
	"os"
	"path/filepath"

	"compliancecheck/internal/model"
)

var suidScanDirs = []string{
	"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin",
}

// knownCommonSUID are binaries that are SUID/SGID on virtually every
// system by design - listed here so they can be reported at INFO rather
// than the same severity as an unrecognized one, since flagging every
// normal system's passwd/sudo/ping identically to a genuine backdoor
// candidate would bury the signal that actually matters.
var knownCommonSUID = map[string]bool{
	"passwd": true, "sudo": true, "su": true, "ping": true, "ping6": true,
	"mount": true, "umount": true, "newgrp": true, "gpasswd": true,
	"chsh": true, "chfn": true, "chage": true, "crontab": true,
	"pkexec": true, "fusermount": true, "fusermount3": true, "unix_chkpwd": true,
	"sudoedit": true, "at": true, "traceroute6.iputils": true,
}

func scanSUIDFiles() []model.Finding {
	var out []model.Finding
	for _, dir := range suidScanDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			mode := info.Mode()
			if mode&os.ModeSetuid == 0 && mode&os.ModeSetgid == 0 {
				continue
			}

			bits := ""
			if mode&os.ModeSetuid != 0 {
				bits += "SUID"
			}
			if mode&os.ModeSetgid != 0 {
				if bits != "" {
					bits += "+"
				}
				bits += "SGID"
			}

			sev := model.SeverityLow
			detail := bits + " binary - normal for a small known set of system tools, worth a glance if unrecognized."
			if knownCommonSUID[e.Name()] {
				sev = model.SeverityInfo
				detail = bits + " binary - one of the common system tools that's normally set this way."
			}

			f := model.NewFinding(model.CategoryStorage, "suid_sgid_binary", bits+" binary", sev)
			f.Source = "storage.suid"
			f.Location = filepath.Join(dir, e.Name())
			f.Detail = detail
			f.Evidence["mode"] = mode.Perm().String()
			out = append(out, f)
		}
	}
	return out
}
