// internal/cipher/detect.go
package cipher

import (
	"strings"
	"unicode/utf8"

	"compliancecheck/internal/langdetect"
)

type EncodingMatch struct {
	Type      string `json:"type"` // "base64" | "hex" | "base32" | "binary" | "url_encoded" | "morse" | "octal" | "decimal" | "hex_xor"
	Sample    string `json:"sample"`
	Decoded   string `json:"decoded,omitempty"`
	Decodable bool   `json:"decodable"`
	Key       string `json:"key,omitempty"` // populated when a key had to be recovered (currently: hex_xor)
	// LooksMeaningful is true when the decoded output looks like real text
	// (not just valid-but-arbitrary bytes) - e.g. a decoded git blob hash
	// is "decodable" but not "meaningful"; a decoded base64 sentence is both.
	LooksMeaningful bool `json:"looks_meaningful"`
	Position        int  `json:"position"`
}

type Report struct {
	Encodings      []EncodingMatch `json:"encodings,omitempty"`
	ClassicalCrack *CrackResult    `json:"classical_crack,omitempty"`
}

const maxEncodingMatches = 30 // cap so a file full of hashes doesn't dominate the report

// Detect scans text for encoded substrings (base64/hex/base32/binary/URL/
// morse/octal/decimal) and, separately, attempts classical cipher cracking
// on the text as a whole (Caesar/ROT13/Atbash/Vigenère) - only meaningful
// if the text didn't already read as a known language (callers typically
// gate this).
func Detect(text string, det *langdetect.Detector) Report {
	var rep Report
	rep.Encodings = detectEncodings(text, det)
	if result, ok := CrackClassical(text, det); ok {
		rep.ClassicalCrack = &result
	}
	return rep
}

func detectEncodings(text string, det *langdetect.Detector) []EncodingMatch {
	var out []EncodingMatch

	// add reports every syntactic match (even undecodable/meaningless ones) -
	// used for encodings whose candidate regex is specific enough that a
	// match is inherently interesting (base64/hex/base32/binary/URL).
	add := func(typ string, loc []int, decode func(string) (string, error)) {
		if len(out) >= maxEncodingMatches {
			return
		}
		raw := text[loc[0]:loc[1]]
		m := EncodingMatch{Type: typ, Sample: truncate(raw, 60), Position: loc[0]}
		if decoded, err := decode(raw); err == nil {
			m.Decodable = true
			m.LooksMeaningful = looksMeaningfulText(decoded)
			m.Decoded = truncate(decoded, 200)
		}
		out = append(out, m)
		return
	}

	// addIfMeaningful only reports a match when it actually decodes to
	// readable text - used for encodings whose candidate regex is broad
	// enough to match plenty of ordinary content by chance (decimal/octal
	// number sequences, in particular: "1 2 3 4 5" syntactically matches
	// the decimal-ASCII pattern but is almost always just... numbers).
	// Reporting every syntactic hit would recreate the false-positive
	// flood this project has already had to fix twice for other checks.
	addIfMeaningful := func(typ string, loc []int, decode func(string) (string, error)) {
		if len(out) >= maxEncodingMatches {
			return
		}
		raw := text[loc[0]:loc[1]]
		decoded, err := decode(raw)
		if err != nil || !looksMeaningfulText(decoded) {
			return
		}
		out = append(out, EncodingMatch{
			Type: typ, Sample: truncate(raw, 60), Position: loc[0],
			Decodable: true, LooksMeaningful: true, Decoded: truncate(decoded, 200),
		})
	}

	for _, loc := range base64CandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		add("base64", loc, Base64Decode)
	}
	for _, loc := range hexCandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		raw := text[loc[0]:loc[1]]
		decoded, err := HexDecode(raw)
		meaningful := err == nil && looksMeaningfulText(decoded)
		if err == nil && meaningful {
			out = append(out, EncodingMatch{Type: "hex", Sample: truncate(raw, 60), Position: loc[0],
				Decodable: true, LooksMeaningful: true, Decoded: truncate(decoded, 200)})
			continue
		}
		// Direct hex decode isn't readable text - try single-byte XOR on top
		// of it before giving up, since "hex-encoded, then XOR-obfuscated"
		// is a common real pattern (e.g. malware config strings).
		if crack, ok := CrackXORSingleByte(raw, det); ok {
			out = append(out, EncodingMatch{Type: "hex_xor", Sample: truncate(raw, 60), Position: loc[0],
				Decodable: true, LooksMeaningful: true, Decoded: truncate(crack.Plaintext, 200), Key: crack.Key})
			continue
		}
		out = append(out, EncodingMatch{Type: "hex", Sample: truncate(raw, 60), Position: loc[0], Decodable: err == nil})
	}
	for _, loc := range base32CandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		add("base32", loc, Base32Decode)
	}
	for _, loc := range binaryCandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		add("binary", loc, BinaryDecode)
	}
	for _, loc := range urlEncodedCandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		add("url_encoded", loc, URLDecode)
	}
	for _, loc := range morseCandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		addIfMeaningful("morse", loc, MorseDecode)
	}
	for _, loc := range octalCandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		addIfMeaningful("octal", loc, OctalDecode)
	}
	for _, loc := range decimalCandidateRe.FindAllStringIndex(text, maxEncodingMatches) {
		addIfMeaningful("decimal", loc, DecimalDecode)
	}

	return out
}

// looksMeaningfulText is a lighter-weight cousin of the extraction quality
// gate used elsewhere: decoded bytes that are mostly printable text (not
// binary data a base64/hex blob might legitimately also represent, like an
// embedded image, encryption ciphertext, or a hash) are worth surfacing as
// "meaningful."
//
// Works at the byte level deliberately, not by ranging over the string as
// runes: casting arbitrary decoded bytes to a Go string and iterating with
// unicode.IsPrint is a trap - invalid UTF-8 byte sequences decode as the
// replacement character U+FFFD, which IS "printable," so random binary
// output would otherwise pass this check (caught during testing: real
// docx/PDF binary data was being reported as "meaningful decoded text").
func looksMeaningfulText(s string) bool {
	b := []byte(s)
	if len(strings.TrimSpace(s)) < 4 {
		return false
	}
	printable := 0
	for _, c := range b {
		switch {
		case c == 0x00:
			return false // NUL byte: definitely binary, bail immediately
		case c == '\t' || c == '\n' || c == '\r':
			printable++
		case c >= 0x20 && c < 0x7f:
			printable++
		}
	}
	asciiRatio := float64(printable) / float64(len(b))
	if asciiRatio > 0.85 {
		return true
	}
	// Allow genuinely accented/non-Latin decoded text through, but only if
	// it's actually valid UTF-8 (not bytes that happen to decode as one or
	// two replacement characters among mostly-binary content).
	return asciiRatio > 0.60 && utf8.Valid(b) && !strings.ContainsRune(s, utf8.RuneError)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
