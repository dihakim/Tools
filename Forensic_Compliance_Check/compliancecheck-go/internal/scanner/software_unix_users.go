//go:build linux || darwin

// internal/scanner/software_unix_users.go
//
// Reads /etc/passwd directly (present and readable on both Linux and
// macOS) rather than shelling out to `dscl`/`getent` - pure stdlib, no
// exec. On macOS this only sees local accounts that still have a
// /etc/passwd entry; accounts purely in Open Directory won't show up
// here - a real gap, noted rather than hidden.
//
// This is the "who else uses this device" scanner from the original ask.
// It reports every real account for manual review (not just flagged
// ones), and separately flags a couple of well-known anomaly patterns:
// a non-root account with UID 0 (privilege-equivalent to root - a classic
// backdoor technique), and system/service accounts that have been given
// an interactive login shell they shouldn't need.
package scanner

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"compliancecheck/internal/model"
)

type passwdEntry struct {
	username string
	uid      int
	gid      int
	gecos    string
	home     string
	shell    string
}

func scanUsers() []model.Finding {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		info := model.NewFinding(model.CategorySoftware, "users_unreadable", "Could not read local account list", model.SeverityInfo)
		info.Source = "software.users"
		info.Detail = err.Error()
		return []model.Finding{info}
	}
	defer f.Close()

	var out []model.Finding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		entry := passwdEntry{
			username: fields[0],
			uid:      uid,
			gid:      gid,
			gecos:    fields[4],
			home:     fields[5],
			shell:    fields[6],
		}
		out = append(out, userFinding(entry))
	}
	return out
}

var noLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true,
	"/usr/bin/false": true, "": true,
}

func userFinding(e passwdEntry) model.Finding {
	sev := model.SeverityClean
	var notes []string

	if e.uid == 0 && e.username != "root" {
		sev = model.SeverityCritical
		notes = append(notes, "non-root account with UID 0 (root-equivalent privileges) - classic backdoor pattern")
	} else if e.uid < 1000 && e.uid != 0 && !noLoginShells[e.shell] {
		// System/service account range (convention, not a hard rule) with an
		// interactive shell it normally wouldn't need.
		sev = model.SeverityLow
		notes = append(notes, "system-range account (uid "+strconv.Itoa(e.uid)+") has an interactive login shell")
	}

	title := "Local user account"
	f := model.NewFinding(model.CategorySoftware, "local_user_account", title, sev)
	f.Source = "software.users"
	f.Location = e.username
	if len(notes) > 0 {
		f.Detail = strings.Join(notes, "; ")
	} else {
		f.Detail = "uid=" + strconv.Itoa(e.uid) + " shell=" + e.shell
	}
	f.Evidence["uid"] = e.uid
	f.Evidence["gid"] = e.gid
	f.Evidence["shell"] = e.shell
	f.Evidence["home"] = e.home
	f.Evidence["gecos"] = e.gecos
	return f
}
