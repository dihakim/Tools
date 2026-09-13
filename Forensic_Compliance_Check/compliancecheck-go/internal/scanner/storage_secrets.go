// internal/scanner/storage_secrets.go
//
// Scans well-known credential file locations under the home directory -
// AWS CLI credentials, .netrc, git-credentials, npm/docker/kube configs.
// These are all plaintext BY DESIGN (the tools that use them read them as
// plain text, with no OS-level encryption involved at all) - this is a
// fundamentally different category from browser-saved-password
// decryption (see software_browser.go's comment for that distinction):
// there's no protection here to bypass, just a config file on disk that
// happens to contain a secret, which is the same sensitivity as any other
// file this tool reads and reports on. Finding one is real, actionable
// signal - it's a common real-world leak vector (accidentally committed
// dotfiles, unencrypted home directory backups, shared/multi-user boxes).
package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"compliancecheck/internal/model"
)

type credentialFileCheck struct {
	relPath string
	kind    string
}

var credentialFileChecks = []credentialFileCheck{
	{".aws/credentials", "aws_credentials"},
	{".aws/config", "aws_config"},
	{".netrc", "netrc"},
	{"_netrc", "netrc"}, // Windows-style name
	{".git-credentials", "git_credentials"},
	{".npmrc", "npmrc"},
	{".pypirc", "pypirc"},
	{".docker/config.json", "docker_config"},
	{".kube/config", "kube_config"},
}

func scanCredentialFiles() []model.Finding {
	home := homeDir()
	if home == "" {
		return nil
	}

	var out []model.Finding
	for _, check := range credentialFileChecks {
		path := filepath.Join(home, check.relPath)
		info, err := os.Stat(path)
		if err != nil {
			continue // not present - the common case, no finding needed either way
		}
		out = append(out, inspectCredentialFile(path, check.kind, info)...)
	}
	return out
}

func inspectCredentialFile(path, kind string, info os.FileInfo) []model.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(data)

	hasSecret := false
	detail := ""
	switch kind {
	case "aws_credentials":
		hasSecret = strings.Contains(text, "aws_secret_access_key")
		detail = "AWS CLI credentials file - contains a plaintext secret access key by design. If this system is shared or backed up unencrypted, rotate the key."
	case "netrc":
		hasSecret = strings.Contains(text, "password")
		detail = ".netrc stores plaintext passwords by design, used automatically by curl/ftp/git and other tools."
	case "git_credentials":
		hasSecret = strings.Contains(text, "://") && strings.Contains(text, "@")
		detail = "git credential store - URLs here embed plaintext username:password/token by design."
	case "npmrc":
		hasSecret = strings.Contains(text, "_authToken") || strings.Contains(text, "_password")
		detail = "npm config contains a registry auth token/password."
	case "pypirc":
		hasSecret = strings.Contains(text, "password")
		detail = "PyPI upload credentials file contains a plaintext password."
	case "docker_config":
		hasSecret = credentialFileHasDockerAuth(text)
		detail = "Docker config contains registry auth (base64-encoded, NOT encrypted - trivially reversible)."
	case "kube_config":
		hasSecret = strings.Contains(text, "client-key-data") || strings.Contains(text, "token:")
		detail = "Kubernetes config contains embedded client key material or a bearer token."
	default:
		detail = "Present."
	}

	sev := model.SeverityLow
	if hasSecret {
		sev = model.SeverityHigh
	}

	f := model.NewFinding(model.CategoryStorage, "credential_file_"+kind, "Credential file found: "+filepath.Base(path), sev)
	f.Source = "storage.secrets"
	f.Location = path
	f.Detail = detail
	f.Evidence["contains_secret_material"] = hasSecret
	f.Evidence["size_bytes"] = info.Size()
	return []model.Finding{f}
}

// credentialFileHasDockerAuth checks Docker's config.json for a non-empty
// "auth" field under any registry entry, without attempting to decode it
// (it's base64 of "user:pass", not encrypted, but decoding it would mean
// handling an actual credential value rather than just detecting presence).
func credentialFileHasDockerAuth(text string) bool {
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal([]byte(text), &cfg) != nil {
		return false
	}
	for _, a := range cfg.Auths {
		if a.Auth != "" {
			return true
		}
	}
	return false
}
