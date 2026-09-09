// internal/cipher/encodings.go
//
// Encode/decode/detect for common text encodings. These aren't "ciphers"
// in the cryptographic sense (no key, not meant for secrecy) but they're
// exactly what a forensic scanner needs to recognize: base64/hex-encoded
// payloads pasted into files, URL-encoded strings, etc. Detection finds
// candidate substrings in a larger text; decode is always attempted so a
// finding can carry the actual plaintext, not just "this looks encoded."
package cipher

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
)

// --- Base64 ---

func Base64Encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func Base64Decode(s string) (string, error) {
	// Try standard, then URL-safe, then raw (no padding) variants.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", errDecodeFailed
}

var base64CandidateRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// --- Hex ---

func HexEncode(s string) string { return hex.EncodeToString([]byte(s)) }

func HexDecode(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

var hexCandidateRe = regexp.MustCompile(`\b[0-9A-Fa-f]{16,}\b`)

// --- Base32 ---

func Base32Encode(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }

func Base32Decode(s string) (string, error) {
	b, err := base32.StdEncoding.DecodeString(strings.ToUpper(s))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

var base32CandidateRe = regexp.MustCompile(`\b[A-Z2-7]{16,}={0,6}\b`)

// --- Binary (space-separated 8-bit groups, e.g. "01001000 01101001") ---

func BinaryEncode(s string) string {
	var out []string
	for _, b := range []byte(s) {
		bits := ""
		for i := 7; i >= 0; i-- {
			if b&(1<<i) != 0 {
				bits += "1"
			} else {
				bits += "0"
			}
		}
		out = append(out, bits)
	}
	return strings.Join(out, " ")
}

func BinaryDecode(s string) (string, error) {
	groups := strings.Fields(s)
	if len(groups) == 0 {
		return "", errDecodeFailed
	}
	var out []byte
	for _, g := range groups {
		if len(g) != 8 {
			return "", errDecodeFailed
		}
		var b byte
		for _, c := range g {
			b <<= 1
			switch c {
			case '1':
				b |= 1
			case '0':
			default:
				return "", errDecodeFailed
			}
		}
		out = append(out, b)
	}
	return string(out), nil
}

var binaryCandidateRe = regexp.MustCompile(`\b(?:[01]{8}[ ]?){3,}\b`)

// --- URL / percent-encoding ---

func URLEncode(s string) string { return url.QueryEscape(s) }

func URLDecode(s string) (string, error) { return url.QueryUnescape(s) }

var urlEncodedCandidateRe = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){3,}`)

var errDecodeFailed = &decodeError{}

type decodeError struct{}

func (*decodeError) Error() string { return "decode failed" }
