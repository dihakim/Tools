// internal/forensics/tools.go
//
// Small standalone forensic utilities that don't fit the main scan
// pipeline (they're on-demand tools a person reaches for during an
// investigation, not automated checks that run over every file):
// file hashing, hash-type identification from a bare string, and JWT
// decoding. All pure stdlib.
package forensics

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type FileHashes struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	MD5       string `json:"md5"`
	SHA1      string `json:"sha1"`
	SHA256    string `json:"sha256"`
	SHA512    string `json:"sha512"`
}

// HashFile computes MD5/SHA1/SHA256/SHA512 in one pass over the file - the
// standard forensic "what is this file's fingerprint" operation, used for
// integrity verification and comparing against known-hash databases
// (which this tool doesn't ship, since that would need a live lookup).
func HashFile(path string) (FileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileHashes{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return FileHashes{}, err
	}

	md5h, sha1h, sha256h, sha512h := md5.New(), sha1.New(), sha256.New(), sha512.New()
	buf := make([]byte, 1024*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			md5h.Write(chunk)
			sha1h.Write(chunk)
			sha256h.Write(chunk)
			sha512h.Write(chunk)
		}
		if err != nil {
			break
		}
	}

	return FileHashes{
		Path:      path,
		SizeBytes: info.Size(),
		MD5:       hex.EncodeToString(md5h.Sum(nil)),
		SHA1:      hex.EncodeToString(sha1h.Sum(nil)),
		SHA256:    hex.EncodeToString(sha256h.Sum(nil)),
		SHA512:    hex.EncodeToString(sha512h.Sum(nil)),
	}, nil
}

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// IdentifyHash guesses likely algorithm(s) for a bare hash string, purely
// from length and charset - the same heuristic every "hash identifier"
// tool uses (there's no way to be certain from the string alone, since
// e.g. MD5 and NTLM are both 32 hex chars; this returns all plausible
// matches rather than a single false-confident guess).
func IdentifyHash(hash string) []string {
	h := strings.TrimSpace(hash)
	var matches []string

	if hexRe.MatchString(h) {
		switch len(h) {
		case 32:
			matches = append(matches, "MD5", "NTLM", "MD4", "LM hash")
		case 40:
			matches = append(matches, "SHA-1", "MySQL5")
		case 56:
			matches = append(matches, "SHA-224", "SHA3-224")
		case 64:
			matches = append(matches, "SHA-256", "SHA3-256")
		case 96:
			matches = append(matches, "SHA-384", "SHA3-384")
		case 128:
			matches = append(matches, "SHA-512", "SHA3-512")
		case 8:
			matches = append(matches, "CRC32")
		}
	}
	if strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$") {
		matches = append(matches, "bcrypt")
	}
	if strings.HasPrefix(h, "$1$") {
		matches = append(matches, "MD5crypt")
	}
	if strings.HasPrefix(h, "$6$") {
		matches = append(matches, "SHA-512crypt")
	}
	if strings.HasPrefix(h, "$argon2") {
		matches = append(matches, "Argon2")
	}
	if len(h) == 44 && strings.HasSuffix(h, "=") {
		matches = append(matches, "SHA-256 (base64-encoded)")
	}

	return matches
}

type JWTResult struct {
	Valid    bool           `json:"valid_structure"`
	Header   map[string]any `json:"header,omitempty"`
	Payload  map[string]any `json:"payload,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// DecodeJWT decodes a JWT's header and payload WITHOUT verifying the
// signature (there's no way to verify without the signing key/secret,
// which this tool never has) - this is purely for inspection, exactly
// what a forensic investigator needs when they find a token in a log,
// config file, or captured traffic. Flags a couple of well-known red
// flags: alg=none (signature bypass), and an expired/not-yet-valid token.
func DecodeJWT(token string) JWTResult {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return JWTResult{Error: "not a JWT - expected 3 dot-separated segments (header.payload.signature), got " + fmt.Sprint(len(parts))}
	}

	header, err := decodeJWTSegment(parts[0])
	if err != nil {
		return JWTResult{Error: "could not decode header: " + err.Error()}
	}
	payload, err := decodeJWTSegment(parts[1])
	if err != nil {
		return JWTResult{Error: "could not decode payload: " + err.Error()}
	}

	res := JWTResult{Valid: true, Header: header, Payload: payload}

	if alg, ok := header["alg"].(string); ok && strings.EqualFold(alg, "none") {
		res.Warnings = append(res.Warnings, "alg=none: this token claims no signature is needed - a classic JWT signature-bypass attack pattern. Never trust a token like this.")
	}
	if exp, ok := numericClaim(payload, "exp"); ok {
		if time.Now().After(time.Unix(int64(exp), 0)) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Token expired at %s", time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)))
		}
	}
	if nbf, ok := numericClaim(payload, "nbf"); ok {
		if time.Now().Before(time.Unix(int64(nbf), 0)) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Token not valid until %s", time.Unix(int64(nbf), 0).UTC().Format(time.RFC3339)))
		}
	}

	return res
}

func numericClaim(payload map[string]any, key string) (float64, bool) {
	v, ok := payload[key]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64) // encoding/json decodes all JSON numbers as float64
	return f, ok
}

func decodeJWTSegment(seg string) (map[string]any, error) {
	// JWT uses base64url without padding.
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		// Some producers still include padding - try standard as a fallback.
		b, err = base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return nil, err
		}
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
