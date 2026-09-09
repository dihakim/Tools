// internal/cipher/crack.go
//
// Automatic decoding for classical ciphers when no key is supplied - the
// "auto decode if there's a key/code" requirement. Every candidate
// decode, regardless of how it was derived, is validated against
// internal/langdetect before being reported as successful: chi-squared
// scoring picks the best candidate shift/key, but only a result that
// actually reads as a real supported language is returned as "cracked."
// This matters as much as the cracking itself - reporting a low-confidence
// guess as a confident decode would just recreate the false-positive
// problem the rest of this tool has been careful to avoid.
package cipher

import (
	"compliancecheck/internal/langdetect"
)

type CrackResult struct {
	Method     string  `json:"method"`               // "caesar" | "rot13" | "atbash" | "vigenere"
	Key        string  `json:"key,omitempty"`         // shift number (as string) or recovered Vigenère key
	Plaintext  string  `json:"plaintext"`
	Language   string  `json:"language,omitempty"`
	Confidence float64 `json:"confidence"`
}

// CrackClassical tries every classical method this package supports and
// returns the best validated result, if any. ok=false means nothing
// decoded to a recognizable language - the text likely isn't one of
// these ciphers (or uses a longer/more complex key than attempted).
func CrackClassical(text string, det *langdetect.Detector) (CrackResult, bool) {
	var best CrackResult
	found := false

	consider := func(candidate CrackResult) {
		lr := det.Detect(candidate.Plaintext)
		// Require meaningfully more confidence than plain language detection
		// would - this function evaluates ~25+ Caesar shifts plus Vigenère
		// candidates, and with that many trials even a modest per-trial false
		// positive rate compounds (confirmed during testing: a 3-letter
		// spurious Vigenère key validated at 0.14 confidence against a
		// 0.12 threshold). A single flat cutoff isn't enough on its own.
		if lr.Language == "" || lr.Confidence < 0.20 {
			return
		}
		candidate.Language = lr.Language
		candidate.Confidence = lr.Confidence
		if !found || candidate.Confidence > best.Confidence {
			best = candidate
			found = true
		}
	}

	// Caesar: brute force all 25 non-trivial shifts (0 is a no-op).
	for shift := 1; shift < 26; shift++ {
		decoded := CaesarDecode(text, shift)
		consider(CrackResult{Method: "caesar", Key: itoa(shift), Plaintext: decoded})
	}

	// Atbash: no key, single trial.
	consider(CrackResult{Method: "atbash", Plaintext: Atbash(text)})

	// Vigenère: guess key length via average Index of Coincidence across
	// candidate lengths 2-12, then recover each column's shift via
	// chi-squared, then validate the full decode.
	if key, ok := crackVigenereKey(text); ok {
		decoded := VigenereDecode(text, key)
		consider(CrackResult{Method: "vigenere", Key: key, Plaintext: decoded})
	}

	return best, found
}

func crackVigenereKey(text string) (string, bool) {
	letters := onlyLetters(text)
	if len(letters) < 100 {
		// Index-of-Coincidence key-length detection needs enough letters per
		// column to be statistically meaningful (well under this, short
		// samples produce spurious peaks - as verified: a 65-letter sample
		// falsely "detected" a 3-letter key here during testing). Below this
		// length, don't guess - report no crack rather than a wrong one.
		return "", false
	}

	type candidate struct {
		length int
		avgIC  float64
	}
	var candidates []candidate
	for keyLen := 2; keyLen <= 12; keyLen++ {
		var totalIC float64
		for col := 0; col < keyLen; col++ {
			var stream []rune
			for i := col; i < len(letters); i += keyLen {
				stream = append(stream, letters[i])
			}
			totalIC += indexOfCoincidence(stream)
		}
		candidates = append(candidates, candidate{keyLen, totalIC / float64(keyLen)})
	}

	// The correct key length should stand out as a clear peak (natural-language
	// IC ~0.06-0.07) above the surrounding noise floor (~0.038-0.045 for
	// random-looking columns at wrong lengths) - not just the highest of a
	// tightly clustered set, which is what a false positive looks like.
	best := candidates[0]
	icByLength := map[int]float64{}
	var sum float64
	for _, c := range candidates {
		icByLength[c.length] = c.avgIC
		if c.avgIC > best.avgIC {
			best = c
		}
		sum += c.avgIC
	}
	mean := sum / float64(len(candidates))
	if best.avgIC < 0.058 || best.avgIC-mean < 0.01 {
		return "", false
	}

	// Any multiple of the TRUE key length also shows elevated IC (each of its
	// columns is itself a union of true-period columns, still monoalphabetic),
	// so the true period is often a smaller divisor of whatever length won
	// above, not the length itself - verified during testing, where a 6-letter
	// key was detected as length 12. Prefer the smallest divisor that's still
	// clearly a strong candidate.
	bestLength := best.length
	for divisor := 2; divisor < best.length; divisor++ {
		if best.length%divisor != 0 {
			continue
		}
		if ic, ok := icByLength[divisor]; ok && ic >= best.avgIC*0.85 {
			bestLength = divisor
			break
		}
	}

	key := make([]byte, bestLength)
	for col := 0; col < bestLength; col++ {
		var stream []rune
		for i := col; i < len(letters); i += bestLength {
			stream = append(stream, letters[i])
		}
		key[col] = byte('A' + bestShiftForColumn(stream))
	}
	return string(key), true
}

// bestShiftForColumn finds the Caesar shift (0-25) that minimizes
// chi-squared against English letter frequency for one Vigenère column.
func bestShiftForColumn(column []rune) int {
	bestShift := 0
	bestScore := 1e18
	s := string(column)
	for shift := 0; shift < 26; shift++ {
		decoded := CaesarDecode(s, shift)
		score := chiSquared(decoded)
		if score < bestScore {
			bestScore = score
			bestShift = shift
		}
	}
	return bestShift
}

// CrackVigenereOnly attempts only Vigenère cracking (used by the "decode
// with this cipher, but I don't know the key" UI path, where the person
// has already told us which cipher to assume rather than asking us to
// guess among all of them).
func CrackVigenereOnly(text string, det *langdetect.Detector) (CrackResult, bool) {
	key, ok := crackVigenereKey(text)
	if !ok {
		return CrackResult{}, false
	}
	decoded := VigenereDecode(text, key)
	lr := det.Detect(decoded)
	if lr.Language == "" || lr.Confidence < 0.20 {
		return CrackResult{Method: "vigenere", Key: key, Plaintext: decoded}, false
	}
	return CrackResult{Method: "vigenere", Key: key, Plaintext: decoded, Language: lr.Language, Confidence: lr.Confidence}, true
}

// CaesarCandidate is one of the 26 possible Caesar shifts, scored so a UI
// can show all of them and let a person pick, not just the single "best"
// guess - useful when the auto-pick is wrong (short/unusual text) but a
// human can eyeball the list and spot the real one.
type CaesarCandidate struct {
	Shift      int     `json:"shift"`
	Plaintext  string  `json:"plaintext"`
	Language   string  `json:"language,omitempty"`
	Confidence float64 `json:"confidence"`
}

// AllCaesarShifts returns every non-trivial shift (1-25) with its language
// score, sorted best-first, so a UI can present the full candidate list.
func AllCaesarShifts(text string, det *langdetect.Detector) []CaesarCandidate {
	candidates := make([]CaesarCandidate, 0, 25)
	for shift := 1; shift < 26; shift++ {
		decoded := CaesarDecode(text, shift)
		lr := det.Detect(decoded)
		candidates = append(candidates, CaesarCandidate{
			Shift: shift, Plaintext: decoded, Language: lr.Language, Confidence: lr.Confidence,
		})
	}
	sortCandidatesByConfidence(candidates)
	return candidates
}

func sortCandidatesByConfidence(c []CaesarCandidate) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j].Confidence > c[j-1].Confidence; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}
