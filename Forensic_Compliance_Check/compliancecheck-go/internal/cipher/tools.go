// internal/cipher/tools.go
//
// A single dispatch layer over every encode/decode function in this
// package, keyed by method name - what the web UI's manual cipher tools
// call. Kept separate from detect.go/crack.go (which are about automatic
// detection) because this is explicitly the "person already knows what
// cipher it is" path.
package cipher

import (
	"fmt"
	"strconv"
	"strings"

	"compliancecheck/internal/langdetect"
)

var SupportedMethods = []string{
	"base64", "hex", "base32", "binary", "url",
	"rot13", "atbash", "caesar", "vigenere",
	"morse", "octal", "decimal", "leetspeak", "xor",
}

type DecodeResult struct {
	Method     string             `json:"method"`
	Success    bool               `json:"success"`
	Plaintext  string             `json:"plaintext,omitempty"`
	Note       string             `json:"note,omitempty"`
	KeyUsed    string             `json:"key_used,omitempty"`
	Candidates []CaesarCandidate  `json:"candidates,omitempty"` // populated for keyless caesar attempts
	Error      string             `json:"error,omitempty"`
}

// Decode dispatches to the right cipher by name. key is optional for
// rot13/atbash (no key exists) and for caesar/vigenere (triggers an
// auto-crack attempt instead of a direct decode) - this is exactly the
// "select the cipher, but I don't know the key" path.
func Decode(method, text, key string, det *langdetect.Detector) DecodeResult {
	method = strings.ToLower(strings.TrimSpace(method))
	res := DecodeResult{Method: method}

	switch method {
	case "base64":
		p, err := Base64Decode(text)
		return finishDecode(res, p, err)
	case "hex":
		p, err := HexDecode(text)
		return finishDecode(res, p, err)
	case "base32":
		p, err := Base32Decode(text)
		return finishDecode(res, p, err)
	case "binary":
		p, err := BinaryDecode(text)
		return finishDecode(res, p, err)
	case "url":
		p, err := URLDecode(text)
		return finishDecode(res, p, err)
	case "morse":
		p, err := MorseDecode(text)
		return finishDecode(res, p, err)
	case "octal":
		p, err := OctalDecode(text)
		return finishDecode(res, p, err)
	case "decimal":
		p, err := DecimalDecode(text)
		return finishDecode(res, p, err)

	case "rot13":
		res.Success = true
		res.Plaintext = ROT13(text)
		res.Note = "ROT13 has no key - it's its own inverse, so encode and decode are the same operation."
		return res

	case "atbash":
		res.Success = true
		res.Plaintext = Atbash(text)
		res.Note = "Atbash has no key - it's a fixed mirror substitution (A<->Z, B<->Y, ...)."
		return res

	case "leetspeak":
		res.Success = true
		res.Plaintext = LeetspeakReverse(text)
		res.Note = "Leetspeak isn't a strict reversible cipher (e.g. '1' could mean 'i' or 'l') - this is a best-effort common-substitution reversal, not a guaranteed-correct decode."
		return res

	case "xor":
		if strings.TrimSpace(key) == "" {
			crack, ok := CrackXORSingleByte(text, det)
			if !ok {
				res.Note = "No key given, and brute-forcing all 255 single-byte XOR keys found no confident match. Input must be hex-encoded ciphertext; this only cracks single-byte keys, not repeating multi-byte keys."
				return res
			}
			res.Success = true
			res.Plaintext = crack.Plaintext
			res.KeyUsed = crack.Key + " (decimal byte value)"
			res.Note = "No key given - brute-forced all 255 single-byte XOR keys and validated the result as real text."
			return res
		}
		keyByte, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || keyByte < 0 || keyByte > 255 {
			res.Error = "XOR key must be a byte value 0-255, got: " + key
			return res
		}
		p, err := XORDecodeHex(text, byte(keyByte))
		if err != nil {
			res.Error = "input must be hex-encoded ciphertext: " + err.Error()
			return res
		}
		res.Success = true
		res.Plaintext = p
		res.KeyUsed = strconv.Itoa(keyByte)
		return res

	case "caesar":
		if strings.TrimSpace(key) == "" {
			// No key given: brute-force all shifts and let the caller see the
			// full ranked list, since the "best" guess can be wrong on short text.
			candidates := AllCaesarShifts(text, det)
			res.Candidates = candidates
			if len(candidates) > 0 && candidates[0].Confidence >= 0.20 {
				res.Success = true
				res.Plaintext = candidates[0].Plaintext
				res.KeyUsed = strconv.Itoa(candidates[0].Shift)
				res.Note = "No key given - showing the best-scoring shift, plus all 25 candidates to check by eye."
			} else {
				res.Note = "No key given and no shift scored confidently as real text - showing all 25 candidates; check the list by eye."
			}
			return res
		}
		shift, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil {
			res.Error = "Caesar key must be a shift number 0-25, got: " + key
			return res
		}
		res.Success = true
		res.Plaintext = CaesarDecode(text, shift)
		res.KeyUsed = strconv.Itoa(shift)
		return res

	case "vigenere":
		if strings.TrimSpace(key) == "" {
			crack, ok := CrackVigenereOnly(text, det)
			if !ok {
				res.Note = "No key given, and automatic key recovery (Index of Coincidence + frequency analysis) didn't find a confident match - text may be too short, or this may not be Vigenère at all."
				if crack.Key != "" {
					res.Note += " Best guess (unvalidated): key \"" + crack.Key + "\"."
				}
				return res
			}
			res.Success = true
			res.Plaintext = crack.Plaintext
			res.KeyUsed = crack.Key
			res.Note = "No key given - automatically recovered via cryptanalysis (Index of Coincidence for key length, chi-squared frequency analysis per column)."
			return res
		}
		res.Success = true
		res.Plaintext = VigenereDecode(text, key)
		res.KeyUsed = key
		return res

	default:
		res.Error = "unknown method: " + method + " (supported: " + strings.Join(SupportedMethods, ", ") + ")"
		return res
	}
}

// Analyze is the "just tell me what this is" entry point: language
// detection on the raw text, full classical-cipher crack attempt, and
// encoding-pattern detection, all in one call - the "auto detect + decode
// -> likely ciphers + most likely meaning" workflow.
type AnalyzeResult struct {
	InputLanguage  *langdetect.Result `json:"input_language,omitempty"` // if the raw text already reads as a known language, it's probably not ciphered
	ClassicalCrack *CrackResult       `json:"classical_crack,omitempty"`
	Encodings      []EncodingMatch    `json:"encodings,omitempty"`
}

func Analyze(text string, det *langdetect.Detector) AnalyzeResult {
	var res AnalyzeResult

	lr := det.Detect(text)
	if lr.Language != "" {
		res.InputLanguage = &lr
	} else if crack, ok := CrackClassical(text, det); ok {
		res.ClassicalCrack = &crack
	}

	res.Encodings = detectEncodings(text, det)
	return res
}

func finishDecode(res DecodeResult, plaintext string, err error) DecodeResult {
	if err != nil {
		res.Error = "decode failed: " + err.Error()
		return res
	}
	res.Success = true
	res.Plaintext = plaintext
	return res
}

type EncodeResult struct {
	Method  string `json:"method"`
	Success bool   `json:"success"`
	Encoded string `json:"encoded,omitempty"`
	Error   string `json:"error,omitempty"`
}

func Encode(method, text, key string) EncodeResult {
	method = strings.ToLower(strings.TrimSpace(method))
	res := EncodeResult{Method: method}

	switch method {
	case "base64":
		res.Success = true
		res.Encoded = Base64Encode(text)
	case "hex":
		res.Success = true
		res.Encoded = HexEncode(text)
	case "base32":
		res.Success = true
		res.Encoded = Base32Encode(text)
	case "binary":
		res.Success = true
		res.Encoded = BinaryEncode(text)
	case "url":
		res.Success = true
		res.Encoded = URLEncode(text)
	case "morse":
		res.Success = true
		res.Encoded = MorseEncode(text)
	case "octal":
		res.Success = true
		res.Encoded = OctalEncode(text)
	case "decimal":
		res.Success = true
		res.Encoded = DecimalEncode(text)
	case "leetspeak":
		res.Success = true
		res.Encoded = ToLeetspeak(text)
	case "rot13":
		res.Success = true
		res.Encoded = ROT13(text)
	case "atbash":
		res.Success = true
		res.Encoded = Atbash(text)
	case "caesar":
		shift, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil {
			res.Error = fmt.Sprintf("Caesar key must be a shift number 0-25, got: %q", key)
			return res
		}
		res.Success = true
		res.Encoded = CaesarEncode(text, shift)
	case "vigenere":
		if strings.TrimSpace(key) == "" {
			res.Error = "Vigenère encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = VigenereEncode(text, key)
	case "xor":
		if strings.TrimSpace(key) == "" {
			res.Error = "XOR encoding requires a key (byte value 0-255)"
			return res
		}
		keyByte, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || keyByte < 0 || keyByte > 255 {
			res.Error = fmt.Sprintf("XOR key must be a byte value 0-255, got: %q", key)
			return res
		}
		res.Success = true
		res.Encoded = XOREncode(text, byte(keyByte))
	default:
		res.Error = "unknown method: " + method + " (supported: " + strings.Join(SupportedMethods, ", ") + ")"
	}
	return res
}
