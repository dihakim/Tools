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
	"compliancecheck/internal/pii"
	"compliancecheck/internal/translate"
)

var SupportedMethods = []string{
	"base64", "hex", "base32", "binary", "url",
	"rot13", "atbash", "caesar", "vigenere",
	"morse", "octal", "decimal", "leetspeak", "xor",
	"railfence", "scytale", "columnar", "playfair",
	"keyboard", "rot47", "beaufort", "autokey",
	// Reference-parity additions (full coverage of the Python framework's
	// cipher_mapping so every cipher the reference ships is available here).
	"braille", "wingdings", "arrow", "simple_symbols", "symbol_lookalikes",
	"vowel_to_number", "emoticons", "two_square", "four_square", "polybius",
	"route_cipher", "rc4", "lfsr", "one_time_pad", "chacha20", "salsa20",
	"enigma", "des", "spn", "tea",
}

// VariantsFor returns the selectable variant names for a cipher method
// (e.g. keyboard layouts, braille grade, LFSR polynomial, static-symbol
// map choice), or nil when the method has no variants. The UI uses this
// to build its variant dropdown.
func VariantsFor(method string) []string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "keyboard":
		return keyboardVariants()
	case "lfsr":
		return []string{"standard", "alternate", "simple"}
	default:
		if vs := staticVariants(method); vs != nil {
			return vs
		}
		return nil
	}
}

type DecodeResult struct {
	Method     string             `json:"method"`
	Success    bool               `json:"success"`
	Plaintext  string             `json:"plaintext,omitempty"`
	Note       string             `json:"note,omitempty"`
	KeyUsed    string             `json:"key_used,omitempty"`
	Candidates []CaesarCandidate  `json:"candidates,omitempty"` // populated for keyless caesar attempts
	PII        []pii.Match        `json:"pii,omitempty"`        // PII detected in the decoded plaintext (names, emails, IDs...)
	Error      string             `json:"error,omitempty"`
}

// Decode dispatches to the right cipher by name. key is optional for
// rot13/atbash (no key exists) and for caesar/vigenere (triggers an
// auto-crack attempt instead of a direct decode) - this is exactly the
// "select the cipher, but I don't know the key" path. variant selects
// among a cipher's optional settings (keyboard layout, braille grade,
// static-symbol map, LFSR polynomial...); pass "" for the default.
// PII in the decoded plaintext is detected and surfaced via
// DecodeResult.PII so a UI can highlight names, emails, IDs etc. the
// decoded text contains.
func Decode(method, text, key, variant string, det *langdetect.Detector) DecodeResult {
	res := decodeInner(method, text, key, variant, det)
	if res.Success && res.Plaintext != "" && piiDetector != nil {
		res.PII = piiMatches(res.Plaintext)
	}
	return res
}

// piiMatches combines regex-rule PII with dictionary name pairs, sorted by
// position so output reads top-to-bottom like the scanned text.
func piiMatches(text string) []pii.Match {
	all := append(piiDetector.Scan(text), pii.MatchNames(text)...)
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].Position < all[j-1].Position; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	return all
}

func decodeInner(method, text, key, variant string, det *langdetect.Detector) DecodeResult {
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

	case "rot47":
		res.Success = true
		res.Plaintext = ROT47(text)
		res.Note = "ROT47 has no key - it's its own inverse, so encode and decode are the same operation."
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

	case "beaufort":
		if strings.TrimSpace(key) == "" {
			crack, ok := CrackBeaufortOnly(text, det)
			if !ok {
				res.Note = "No key given, and automatic key recovery (Index of Coincidence + frequency analysis) didn't find a confident match - text may be too short, or this may not be Beaufort at all."
				if crack.Key != "" {
					res.Note += " Best guess (unvalidated): key \"" + crack.Key + "\"."
				}
				return res
			}
			res.Success = true
			res.Plaintext = crack.Plaintext
			res.KeyUsed = crack.Key
			res.Note = "No key given - automatically recovered via cryptanalysis (Index of Coincidence for key length, mirrored chi-squared per column)."
			return res
		}
		res.Success = true
		res.Plaintext = BeaufortDecode(text, key)
		res.KeyUsed = key
		res.Note = "Beaufort encryption and decryption are the same operation (C = K - P), so encoding and decoding use the identical rule."
		return res

	case "autokey":
		if strings.TrimSpace(key) == "" {
			res.Error = "Autokey has no keyless mode in this port - the plaintext feeds the keystream, so without at least a short seed there is nothing to chain from. For clues, try Analyze on the ciphertext."
			return res
		}
		res.Success = true
		res.Plaintext = AutokeyDecode(text, key)
		res.KeyUsed = key
		res.Note = "Autokey's keystream is the key followed by the recovered plaintext, so spaces and punctuation are carried through while only letters are transformed."
		return res

	case "keyboard":
		if strings.TrimSpace(key) == "" {
			res.Error = "Keyboard shift needs a key: how many steps to shift along the layout (integer, positive = right)."
			return res
		}
		shift, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil {
			res.Error = "Keyboard shift key must be an integer step count, got: " + key
			return res
		}
		layout := keyboardLayoutName(variant)
		res.Success = true
		res.Plaintext = KeyboardDecode(text, shift, layout)
		res.KeyUsed = strconv.Itoa(shift)
		res.Note = "Layout in use: " + layout + "."
		return res

	case "railfence":
		if strings.TrimSpace(key) == "" {
			crack, ok := CrackRailFence(text, det)
			if !ok {
				res.Note = "No key given, and brute-forcing rail counts 2-20 found no decode that reads as real words - text may be too short, or this may not be a rail fence at all."
				return res
			}
			res.Success = true
			res.Plaintext = crack.Plaintext
			res.KeyUsed = crack.Key + " rails"
			res.Note = "No key given - brute-forced rail counts 2-20 and validated the winner as a natural word sequence."
			return res
		}
		rails, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || rails < 2 {
			res.Error = "Rail fence key must be a rail count of at least 2, got: " + key
			return res
		}
		res.Success = true
		res.Plaintext = RailFenceDecode(text, rails)
		res.KeyUsed = strconv.Itoa(rails)
		res.Note = "Transposition output keeps only letters/numbers (uppercased); spaces and punctuation from the original aren't recoverable from the ciphertext."
		return res

	case "scytale":
		if strings.TrimSpace(key) == "" {
			crack, ok := CrackScytale(text, det)
			if !ok {
				res.Note = "No key given, and brute-forcing rod diameters found no decode that reads as real words - text may be too short, or this may not be a scytale cipher at all."
				return res
			}
			res.Success = true
			res.Plaintext = crack.Plaintext
			res.KeyUsed = crack.Key + " diameter"
			res.Note = "No key given - brute-forced rod diameters and validated the winner as a natural word sequence."
			return res
		}
		diameter, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || diameter < 1 {
			res.Error = "Scytale key must be a positive rod diameter, got: " + key
			return res
		}
		res.Success = true
		res.Plaintext = ScytaleDecode(text, diameter)
		res.KeyUsed = strconv.Itoa(diameter)
		res.Note = "Transposition output keeps only letters/numbers (uppercased); spaces and punctuation from the original aren't recoverable from the ciphertext."
		return res

	case "columnar":
		if strings.TrimSpace(key) == "" {
			crack, ok := CrackColumnar(text, det)
			if !ok {
				res.Note = "No key given, and common keywords + column-order permutations found no decode that reads as real words - text may be too short, or this may not be a columnar transposition at all."
				return res
			}
			res.Success = true
			res.Plaintext = crack.Plaintext
			res.KeyUsed = crack.Key
			res.Note = "No key given - tried common keywords plus numeric column-order permutations and validated the winner as a natural word sequence."
			return res
		}
		if strings.TrimSpace(key) == "" {
			res.Error = "columnar key must be a keyword or column-order string, got: " + key
			return res
		}
		res.Success = true
		res.Plaintext = ColumnarDecode(text, key)
		res.KeyUsed = key
		res.Note = "Transposition output keeps only letters/numbers (uppercased); spaces and punctuation from the original aren't recoverable from the ciphertext."
		return res

	case "playfair":
		if strings.TrimSpace(key) == "" {
			res.Error = "Playfair has no keyless auto-solve - the 5x5 matrix gives no shortcut attack, so a keyword is required. For clues to the keyword, try Analyze on the ciphertext first."
			return res
		}
		res.Success = true
		res.Plaintext = PlayfairDecode(text, key)
		res.KeyUsed = key
		res.Note = "Playfair output is uppercase letters only (J merged into I); the original spacing/punctuation isn't recoverable. Trailing and consonant-adjacent filler X were stripped heuristically."
		return res

	case "two_square":
		if strings.TrimSpace(key) == "" {
			res.Error = "Two-square needs a key: it's split in two to make the top and bottom 5x5 matrices."
			return res
		}
		res.Success = true
		res.Plaintext = TwoSquareDecode(text, key)
		res.KeyUsed = key
		res.Note = "Two-square output is uppercase letters only (J merged into I); original spacing/punctuation isn't recoverable."
		return res

	case "four_square":
		if strings.TrimSpace(key) == "" {
			res.Error = "Four-square needs a key: 'KEY1,KEY2' (or a single string split in half) for the two keyed matrices."
			return res
		}
		res.Success = true
		res.Plaintext = FourSquareDecode(text, key)
		res.KeyUsed = key
		res.Note = "Four-square output is uppercase letters only (J merged into I); original spacing/punctuation isn't recoverable."
		return res

	case "polybius":
		res.Success = true
		res.Plaintext = PolybiusDecode(text, key)
		if strings.TrimSpace(key) != "" {
			res.KeyUsed = key
		}
		res.Note = "Polybius reads digit pairs (1-5) as row/column in a 5x5 square. An optional key builds a keyed square; J is merged into I."
		return res

	case "route_cipher":
		if strings.TrimSpace(key) == "" {
			res.Error = "Route cipher needs a grid key: \"<rows>x<cols>_<direction>_<start>\", e.g. \"4x4_clockwise_top-left\" (start: top-left/top-right/bottom-left/bottom-right)."
			return res
		}
		res.Success = true
		res.Plaintext = RouteDecode(text, key)
		res.KeyUsed = key
		res.Note = "Route cipher transposes by writing row-by-row and reading a spiral; the key's grid geometry must match what was used to encode."
		return res

	case "rc4":
		if strings.TrimSpace(key) == "" {
			res.Error = "RC4 requires a key (any length; it's normalized to 16 bytes via SHA-256)."
			return res
		}
		p, err := RC4Decode(text, key)
		if err != nil {
			res.Error = "input must be hex-encoded RC4 output: " + err.Error()
			return res
		}
		res.Success = true
		res.Plaintext = p
		res.KeyUsed = key
		res.Note = "RC4 is symmetric - encrypt and decrypt use the identical keystream. Output is hex-encoded bytes (input may be binary)."
		return res

	case "lfsr":
		if strings.TrimSpace(key) == "" {
			res.Error = "LFSR requires a key (number or seed; normalized to a 4-byte register)."
			return res
		}
		p, err := LFSRDecode(text, key, variant)
		if err != nil {
			res.Error = "input must be hex-encoded LFSR output: " + err.Error()
			return res
		}
		res.Success = true
		res.Plaintext = p
		res.KeyUsed = key
		res.Note = "LFSR feedback polynomial: " + lfsrVariantName(variant) + ". Output is hex-encoded keystream-xored bytes."
		return res

	case "one_time_pad":
		if strings.TrimSpace(key) == "" {
			res.Error = "One-time pad requires a key at least as long as the message."
			return res
		}
		p, err := OTPDecode(text, key)
		if err != nil {
			if err == errOTPKeyTooShort {
				res.Error = "one-time pad key must be at least as long as the message."
			} else {
				res.Error = "input must be hex-encoded one-time-pad output: " + err.Error()
			}
			return res
		}
		res.Success = true
		res.Plaintext = p
		res.KeyUsed = key
		res.Note = "One-time pad XORs bytes with the key, starting at the beginning. Never reuse a one-time pad key for real secrets."
		return res

	case "chacha20":
		if strings.TrimSpace(key) == "" {
			res.Error = "ChaCha20 requires a key (hashed to 32 bytes via SHA-256)."
			return res
		}
		p, err := ChaCha20Decode(text, key)
		if err != nil {
			res.Error = "input must be hex-encoded ChaCha20 output: " + err.Error()
			return res
		}
		res.Success = true
		res.Plaintext = p
		res.KeyUsed = key
		res.Note = "ChaCha20 stream ciphers XOR into the keyed keystream; the nonce is derived from the key so encode/decode round-trip without extra input."
		return res

	case "salsa20":
		if strings.TrimSpace(key) == "" {
			res.Error = "Salsa20 requires a key (hashed to 32 bytes via SHA-256)."
			return res
		}
		p, err := Salsa20Decode(text, key)
		if err != nil {
			res.Error = "input must be hex-encoded Salsa20 output: " + err.Error()
			return res
		}
		res.Success = true
		res.Plaintext = p
		res.KeyUsed = key
		res.Note = "Salsa20 stream ciphers XOR into the keyed keystream; the nonce is derived from the key so encode/decode round-trip without extra input."
		return res

	case "enigma":
		res.Success = true
		res.Plaintext = EnigmaDecode(text, key)
		res.KeyUsed = key
		res.Note = "Simplified Enigma (rotors I-II-III, reflector B). The key is rotor start positions, e.g. \"ABC\". The machine is symmetric, so encode and decode are the same operation."
		return res

	case "des":
		if strings.TrimSpace(key) == "" {
			res.Error = "Simple DES requires a key."
			return res
		}
		res.Success = true
		res.Plaintext = DesDecode(text, key)
		res.KeyUsed = key
		res.Note = "Simple DES adds the key value mod 26 per character in 2-char blocks (an educational cipher, not real DES)."
		return res

	case "spn":
		if strings.TrimSpace(key) == "" {
			res.Error = "SPN requires a key."
			return res
		}
		res.Success = true
		res.Plaintext = SpnDecode(text, key)
		res.KeyUsed = key
		res.Note = "Working SPN: two rounds of key-add + ROT13 substitute + reverse in 4-char blocks (an educational cipher)."
		return res

	case "tea":
		if strings.TrimSpace(key) == "" {
			res.Error = "Working TEA requires a key."
			return res
		}
		res.Success = true
		res.Plaintext = TeaDecode(text, key)
		res.KeyUsed = key
		res.Note = "Working TEA adds the key value mod 26 per character in 8-char blocks, preserving spaces/punctuation (an educational cipher, not real TEA)."
		return res

	case "braille", "wingdings", "arrow", "simple_symbols", "symbol_lookalikes", "vowel_to_number", "emoticons":
		res.Success = true
		res.Plaintext = staticDecode(method, variant, text)
		v := variant
		if v == "" {
			if vs := staticVariants(method); len(vs) > 0 {
				v = vs[0]
			}
		}
		res.Note = "Static symbol substitution (\"" + v + "\" map). Unmapped characters pass through unchanged; ambiguous symbols decode to the most common letter."
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
	// Translation is a rough dictionary gloss of the input, when one can be
	// produced: explicitly when the caller requested a language, or as a
	// merged fallback when the input isn't a recognized language and
	// classical cracking found nothing (see webui's analyze endpoint, which
	// fills this in after cipher.Analyze returns).
	Translation *translate.Result `json:"translation,omitempty"`
	// InputPII is PII detected in the raw input text (before any decoding),
	// surfaced so the Analyze panel can flag names, emails, IDs etc. in the
	// pasted text even when no cipher was cracked.
	InputPII []pii.Match `json:"input_pii,omitempty"`
}

func Analyze(text string, det *langdetect.Detector) AnalyzeResult {
	var res AnalyzeResult

	// Raw input PII scan: surface names, emails, IDs etc. in the pasted
	// text regardless of whether it's ciphered.
	if piiDetector != nil {
		res.InputPII = piiMatches(text)
	}

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

func Encode(method, text, key, variant string) EncodeResult {
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
	case "rot47":
		res.Success = true
		res.Encoded = ROT47(text)
	case "keyboard":
		if strings.TrimSpace(key) == "" {
			res.Error = "Keyboard shift encoding requires a key (integer step count)"
			return res
		}
		shift, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil {
			res.Error = fmt.Sprintf("Keyboard shift key must be an integer step count, got: %q", key)
			return res
		}
		res.Success = true
		res.Encoded = KeyboardEncode(text, shift, keyboardLayoutName(variant))
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
	case "beaufort":
		if strings.TrimSpace(key) == "" {
			res.Error = "Beaufort encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = BeaufortEncode(text, key)
	case "autokey":
		if strings.TrimSpace(key) == "" {
			res.Error = "Autokey encoding requires a seed key"
			return res
		}
		res.Success = true
		res.Encoded = AutokeyEncode(text, key)
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
	case "railfence":
		rails, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || rails < 2 {
			res.Error = fmt.Sprintf("Rail fence key must be a rail count of at least 2, got: %q", key)
			return res
		}
		res.Success = true
		res.Encoded = RailFenceEncode(text, rails)
	case "scytale":
		diameter, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || diameter < 1 {
			res.Error = fmt.Sprintf("Scytale key must be a positive rod diameter, got: %q", key)
			return res
		}
		res.Success = true
		res.Encoded = ScytaleEncode(text, diameter)
	case "columnar":
		if strings.TrimSpace(key) == "" {
			res.Error = "Columnar transposition encoding requires a keyword or column-order key"
			return res
		}
		res.Success = true
		res.Encoded = ColumnarEncode(text, key)
	case "playfair":
		if strings.TrimSpace(key) == "" {
			res.Error = fmt.Sprintf("Playfair encoding requires a keyword, got: %q", key)
			return res
		}
		res.Success = true
		res.Encoded = PlayfairEncode(text, key)
	case "two_square":
		if strings.TrimSpace(key) == "" {
			res.Error = "Two-square encoding requires a key (split in two for the matrices)"
			return res
		}
		res.Success = true
		res.Encoded = TwoSquareEncode(text, key)
	case "four_square":
		if strings.TrimSpace(key) == "" {
			res.Error = "Four-square encoding requires a key ('KEY1,KEY2' or a split string)"
			return res
		}
		res.Success = true
		res.Encoded = FourSquareEncode(text, key)
	case "polybius":
		res.Success = true
		res.Encoded = PolybiusEncode(text, key)
	case "route_cipher":
		if strings.TrimSpace(key) == "" {
			res.Error = "Route cipher encoding requires a grid key (\"rowsxcols_direction_start\")"
			return res
		}
		res.Success = true
		res.Encoded = RouteEncode(text, key)
	case "rc4":
		if strings.TrimSpace(key) == "" {
			res.Error = "RC4 encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = RC4Encode(text, key)
	case "lfsr":
		if strings.TrimSpace(key) == "" {
			res.Error = "LFSR encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = LFSREncode(text, key, variant)
	case "one_time_pad":
		if strings.TrimSpace(key) == "" {
			res.Error = "One-time pad encoding requires a key at least as long as the message"
			return res
		}
		enc, err := OTPEncode(text, key)
		if err != nil {
			res.Error = "one-time pad key must be at least as long as the message"
			return res
		}
		res.Success = true
		res.Encoded = enc
	case "chacha20":
		if strings.TrimSpace(key) == "" {
			res.Error = "ChaCha20 encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = ChaCha20Encode(text, key)
	case "salsa20":
		if strings.TrimSpace(key) == "" {
			res.Error = "Salsa20 encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = Salsa20Encode(text, key)
	case "enigma":
		res.Success = true
		res.Encoded = EnigmaEncode(text, key)
	case "des":
		if strings.TrimSpace(key) == "" {
			res.Error = "Simple DES encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = DesEncode(text, key)
	case "spn":
		if strings.TrimSpace(key) == "" {
			res.Error = "SPN encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = SpnEncode(text, key)
	case "tea":
		if strings.TrimSpace(key) == "" {
			res.Error = "Working TEA encoding requires a key"
			return res
		}
		res.Success = true
		res.Encoded = TeaEncode(text, key)
	case "braille", "wingdings", "arrow", "simple_symbols", "symbol_lookalikes", "vowel_to_number", "emoticons":
		res.Success = true
		res.Encoded = staticEncode(method, variant, text)
	default:
		res.Error = "unknown method: " + method + " (supported: " + strings.Join(SupportedMethods, ", ") + ")"
	}
	return res
}
