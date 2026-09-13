//go:build linux || darwin

// internal/scanner/storage_unix_ssh.go
//
// SSH key/config security audit - a classic Unix hardening check (the
// same one `ssh-audit`, Lynis, and CIS benchmarks perform): a private key
// or .ssh directory that's readable/writable by group or others defeats
// SSH's own trust model, since anyone else on the system (or anyone who
// gets a foothold as another user) could read the key or tamper with
// authorized_keys. This only checks permissions and lists what's present
// (key file names, authorized_keys comment fields) - it never reads or
// reports actual private key material.
package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"compliancecheck/internal/model"
)

func scanSSHSecurity() []model.Finding {
	home := homeDir()
	if home == "" {
		return nil
	}
	sshDir := filepath.Join(home, ".ssh")
	info, err := os.Stat(sshDir)
	if err != nil {
		f := model.NewFinding(model.CategoryStorage, "ssh_dir_none", "No ~/.ssh directory found", model.SeverityInfo)
		f.Source = "storage.ssh"
		return []model.Finding{f}
	}

	var out []model.Finding

	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		f := model.NewFinding(model.CategoryStorage, "ssh_dir_permissions", "~/.ssh directory has overly permissive permissions", model.SeverityMedium)
		f.Source = "storage.ssh"
		f.Location = sshDir
		f.Detail = "Mode " + mode.String() + " - group/other should have no access (recommended: 700). Anyone else with a foothold on this system could read or tamper with SSH config/keys."
		f.Evidence["mode"] = mode.String()
		out = append(out, f)
	}

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		path := filepath.Join(sshDir, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		mode := fi.Mode().Perm()

		switch {
		case isLikelyPrivateKeyName(e.Name()):
			sev := model.SeverityClean
			detail := "Private key present, permissions OK (" + mode.String() + ")."
			if mode&0o077 != 0 {
				sev = model.SeverityHigh
				detail = "Private key is readable/writable by group or others (mode " + mode.String() + ", recommended: 600) - this defeats SSH's trust model entirely. Fix with chmod 600."
			}
			f := model.NewFinding(model.CategoryStorage, "ssh_private_key", "SSH private key", sev)
			f.Source = "storage.ssh"
			f.Location = path
			f.Detail = detail
			f.Evidence["mode"] = mode.String()
			out = append(out, f)

		case e.Name() == "authorized_keys":
			out = append(out, scanAuthorizedKeys(path, mode)...)

		case e.Name() == "config":
			if mode&0o022 != 0 {
				f := model.NewFinding(model.CategoryStorage, "ssh_config_permissions", "SSH client config is group/other-writable", model.SeverityMedium)
				f.Source = "storage.ssh"
				f.Location = path
				f.Detail = "Mode " + mode.String() + " - another user could modify your SSH config (e.g. redirect a host, inject ProxyCommand)."
				out = append(out, f)
			}
		}
	}
	return out
}

func isLikelyPrivateKeyName(name string) bool {
	switch name {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return true
	}
	return strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, "_key")
}

func scanAuthorizedKeys(path string, mode os.FileMode) []model.Finding {
	var out []model.Finding
	if mode&0o022 != 0 {
		f := model.NewFinding(model.CategoryStorage, "ssh_authorized_keys_permissions", "authorized_keys is group/other-writable", model.SeverityHigh)
		f.Source = "storage.ssh"
		f.Location = path
		f.Detail = "Mode " + mode.String() + " - another user could add their own key here to gain SSH access as you. Fix with chmod 600."
		out = append(out, f)
	}

	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		keyType := ""
		comment := ""
		if len(fields) >= 2 {
			keyType = fields[0]
		}
		if len(fields) >= 3 {
			comment = strings.Join(fields[2:], " ")
		}
		entry := model.NewFinding(model.CategoryStorage, "ssh_authorized_key_entry", "Authorized key entry", model.SeverityClean)
		entry.Source = "storage.ssh"
		entry.Location = path
		entry.Detail = "Key type: " + keyType + ", comment: " + orDefault(comment, "(none)")
		entry.Evidence["key_type"] = keyType
		entry.Evidence["comment"] = comment
		out = append(out, entry)
	}
	return out
}
