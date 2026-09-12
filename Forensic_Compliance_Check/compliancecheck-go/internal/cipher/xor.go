// internal/cipher/xor.go
//
// Single-byte-key XOR is one of the most common real-world obfuscation
// techniques found in malware droppers, config strings, and staged exfil
// data - it's cheap to implement and, unlike Vigenère, trivial to crack
// without knowing the key: XOR is its own inverse, so brute-forcing all
// 255 possible single-byte keys and checking which one produces readable
// text (same validated-against-real-language approach as Caesar cracking)
// recovers it reliably. Multi-byte XOR keys exist too but need a
// different attack (repeating-key XOR ~ Vigenère on bytes) - not
// implemented here; single-byte is overwhelmingly the common case in
// practice and is what's implemented.
package cipher

import (
	"encoding/hex"
	"strconv"

	"compliancecheck/internal/langdetect"
)

// XOREncode/XORDecode are the same operation - XOR is self-inverse. The
// input/output here is hex-encoded (not raw bytes as text) because
// XOR'd output is typically binary garbage that isn't valid UTF-8, and a
// UI text field needs something displayable/copyable.
func XOREncode(s string, key byte) string {
	return hex.EncodeToString(xorBytes([]byte(s), key))
}

func XORDecodeHex(hexStr string, key byte) (string, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	return string(xorBytes(data, key)), nil
}

func xorBytes(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key
	}
	return out
}

// CrackXORSingleByte brute-forces all 255 non-zero single-byte keys against
// hex-encoded ciphertext and returns the one whose decode validates as real
// language - same validated-crack pattern as Caesar/Vigenère, so a wrong
// key that happens to produce a few readable characters doesn't get
// reported as a confident match.
func CrackXORSingleByte(hexStr string, det *langdetect.Detector) (CrackResult, bool) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return CrackResult{}, false
	}
	var best CrackResult
	found := false
	for key := 1; key < 256; key++ {
		decoded := string(xorBytes(data, byte(key)))
		if !looksMeaningfulText(decoded) || !looksLikeRealSentence(decoded) {
			continue // skip the langdetect call entirely for obviously-binary or word-salad output
		}
		lr := det.Detect(decoded)
		if !validateCrackCandidate(decoded, lr) {
			continue
		}
		if !found || lr.Confidence > best.Confidence {
			best = CrackResult{Method: "xor", Key: strconv.Itoa(key), Plaintext: decoded, Language: lr.Language, Confidence: lr.Confidence}
			found = true
		}
	}
	return best, found
}
