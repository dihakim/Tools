//go:build windows

// internal/scanner/storage_windows_ssh.go
//
// Windows' OpenSSH client (when present) uses the same ~/.ssh layout, but
// "overly permissive" means something different there - NTFS ACLs, not
// POSIX mode bits, and OpenSSH-for-Windows actually enforces stricter
// checks itself (it refuses to use a private key with inherited/Everyone
// ACLs and tells you so). Rather than reimplement ACL-permission logic
// that duplicates what OpenSSH itself already checks, this is an honest
// "not yet implemented" instead of a bit-permission check that wouldn't
// mean anything on this platform.
package scanner

import "compliancecheck/internal/model"

func scanSSHSecurity() []model.Finding {
	f := model.NewFinding(model.CategoryStorage, "ssh_audit_not_implemented", "SSH key security audit not yet implemented on Windows", model.SeverityInfo)
	f.Source = "storage.ssh"
	f.Detail = "Windows uses NTFS ACLs, not POSIX permission bits, for key protection - needs a different check than the Linux/macOS implementation, not yet built."
	return []model.Finding{f}
}
