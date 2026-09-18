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
	"strings"
	"unicode"

	"compliancecheck/internal/langdetect"
	"compliancecheck/internal/ngram"
	"compliancecheck/internal/pii"
)

// piiDetector supports the modest PII-structured-text boost applied to
// crack candidates (see piiBoost): decoded "John Brown" or an email is weak
// but real evidence a decode produced human content, on top of the
// language-based validation that runs first. rules.json is tiny and
// embedded, so sharing one detector package-wide is cheap.
var piiDetector, _ = pii.Load()

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
		if !selfValidatedTransposition[candidate.Method] {
			lr := det.Detect(candidate.Plaintext)
			if !validateCrackCandidate(candidate.Plaintext, lr) {
				return
			}
			candidate.Language = lr.Language
			candidate.Confidence = capConfidence(lr.Confidence + piiBoost(candidate.Plaintext))
		} else {
			// Transposition self-validation already ran (digraph outlier +
			// dictionary coverage); PII is just a modest extra edge for real
			// content (a decoded name/email/IP is human text, not coincidence).
			candidate.Confidence = capConfidence(candidate.Confidence + piiBoost(candidate.Plaintext))
		}
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

	// Beaufort: same key-length detection, mirrored column recovery (see
	// bestBeaufortColumnKey - Beaufort subtracts the key from the plaintext
	// rather than adding it).
	if key, ok := crackBeaufortKey(text, det); ok {
		decoded := BeaufortDecode(text, key)
		consider(CrackResult{Method: "beaufort", Key: key, Plaintext: decoded})
	}

	// Transpositions (rail fence / scytale / columnar) preserve letters but
	// scramble their order, so they use their own validation gate (digraph
	// outlier + dictionary coverage - see transposition.go) rather than the
	// langdetect-based one above, which cannot see through space-free text.
	if crack, ok := CrackRailFence(text, det); ok {
		consider(crack)
	}
	if crack, ok := CrackScytale(text, det); ok {
		consider(crack)
	}
	if crack, ok := CrackColumnar(text, det); ok {
		consider(crack)
	}

	return best, found
}

// selfValidatedTransposition marks crack methods whose results were already
// validated by their own gate (transposition.go's digraph-outlier +
// dictionary-coverage check) rather than by langdetect - the normal
// consider() validation cannot see through their space-free output.
var selfValidatedTransposition = map[string]bool{
	"railfence": true, "scytale": true, "columnar": true,
}

func crackVigenereKey(text string) (string, bool) {
	letters := onlyLetters(text)
	keyLen, ok := polyalphabeticKeyLength(letters)
	if !ok {
		return "", false
	}
	key := make([]byte, keyLen)
	for col := 0; col < keyLen; col++ {
		var stream []rune
		for i := col; i < len(letters); i += keyLen {
			stream = append(stream, letters[i])
		}
		key[col] = byte('A' + bestShiftForColumn(stream))
	}
	return string(key), true
}

// polyalphabeticKeyLength guesses the Vigenère-style key length by picking
// the Index-of-Coincidence peak that stands clearly above the surrounding
// noise floor (see indexOfCoincidence). Both Vigenère and Beaufort share
// this detection: their columns are equally monoalphabetic at the true
// period.
func polyalphabeticKeyLength(letters []rune) (int, bool) {
	if len(letters) < 100 {
		// Index-of-Coincidence key-length detection needs enough letters per
		// column to be statistically meaningful (well under this, short
		// samples produce spurious peaks - as verified: a 65-letter sample
		// falsely "detected" a 3-letter key here during testing). Below this
		// length, don't guess - report no crack rather than a wrong one.
		return 0, false
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
		return 0, false
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

	return bestLength, true
}

// bestShiftForColumn finds the Caesar shift (0-25) that minimizes
// chi-squared against English letter frequency for one Vigenère column.
//
// Unigram frequency (not digraphs) is deliberately used here: a column is
// every N-th letter of the plaintext, so adjacent column letters are NOT
// adjacent in the real text and digraph statistics don't apply - but the
// per-letter distribution is preserved, which is exactly what unigrams
// measure. (Attempted during testing and confirmed harmfully wrong: digraph
// scoring mis-recovers columns because correct column decodes look
// pseudo-random pairwise.)
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

// bestBeaufortColumnKey guesses the Beaufort key letter for one column.
// Beaufort's rule C = (K - P) is a mirror of Vigenère's, so the ciphertext
// letter itself is inverted relative to plaintext and a shift-by-N on the
// ciphertext does NOT land on the plaintext - the candidate plaintexts are
// (K - C) for each key letter K instead of (C - s). (This is why Beaufort
// needs its own column scorer even though it shares Vigenère's key-length
// detection.)
func bestBeaufortColumnKey(column []rune) int {
	bestKey := 0
	bestScore := 1e18
	for k := 0; k < 26; k++ {
		var b strings.Builder
		for _, r := range column {
			off := ((k-int(r-'a'))%26 + 26) % 26 // Go % keeps sign; normalize
			b.WriteRune(rune('a' + off))
		}
		score := chiSquared(b.String())
		if score < bestScore {
			bestScore = score
			bestKey = k
		}
	}
	return bestKey
}

// bestLangScore returns the detector's highest stopword fraction across all
// languages for text - the acceptance signal the crack ultimately gates on.
func bestLangScore(det *langdetect.Detector, text string) float64 {
	if det == nil {
		return 0
	}
	res := det.Detect(text)
	best := 0.0
	for _, s := range res.Scores {
		if s > best {
			best = s
		}
	}
	return best
}

// crackBeaufortKey recovers a Beaufort key with the same Index-of-
// Coincidence length detection as Vigenère, then per-column key-letter
// recovery via the mirrored scorer above. Short columns are inherently
// noisy for chi-squared per-column scoring, so the initial guess is then
// refined hill-climbing each key letter against the SAME signal the crack
// ultimately gates on - the language detector's stopword fraction of the
// fully SPACED decode (word boundaries matter; a letters-only string is a
// single token and scores nothing). A wrong single column typically lowers
// the whole-text score below the acceptance floor, so the climb homes in on
// the English decode.
func crackBeaufortKey(text string, det *langdetect.Detector) (string, bool) {
	letters := onlyLetters(text)
	keyLen, ok := polyalphabeticKeyLength(letters)
	if !ok {
		return "", false
	}
	key := make([]byte, keyLen)
	for col := 0; col < keyLen; col++ {
		var stream []rune
		for i := col; i < len(letters); i += keyLen {
			stream = append(stream, letters[i])
		}
		key[col] = byte('A' + bestBeaufortColumnKey(stream))
	}
	best := bestLangScore(det, BeaufortDecode(text, string(key)))
	improved := true
	for improved && det != nil {
		improved = false
		for col := 0; col < keyLen; col++ {
			for k := byte('A'); k <= 'Z'; k++ {
				if k == key[col] {
					continue
				}
				old := key[col]
				key[col] = k
				if s := bestLangScore(det, BeaufortDecode(text, string(key))); s > best {
					best = s
					improved = true
				} else {
					key[col] = old
				}
			}
		}
	}
	return string(key), true
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
	return CrackResult{
		Method: "vigenere", Key: key, Plaintext: decoded,
		Language: lr.Language, Confidence: capConfidence(lr.Confidence + piiBoost(decoded)),
	}, true
}

// CrackBeaufortOnly is the Beaufort counterpart to CrackVigenereOnly.
func CrackBeaufortOnly(text string, det *langdetect.Detector) (CrackResult, bool) {
	key, ok := crackBeaufortKey(text, det)
	if !ok {
		return CrackResult{}, false
	}
	decoded := BeaufortDecode(text, key)
	lr := det.Detect(decoded)
	if lr.Language == "" || lr.Confidence < 0.20 {
		return CrackResult{Method: "beaufort", Key: key, Plaintext: decoded}, false
	}
	return CrackResult{
		Method: "beaufort", Key: key, Plaintext: decoded,
		Language: lr.Language, Confidence: capConfidence(lr.Confidence + piiBoost(decoded)),
	}, true
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

// looksLikeRealSentence is a stricter secondary gate specifically for
// brute-force crack candidates (Caesar/Vigenère/XOR try dozens to hundreds
// of keys, and langdetect's tokenizer extracts letter-runs from ANYWHERE
// in the text - including single letters embedded in punctuation noise
// like "5)$a" -> "a" - which is far too lenient once you're trying that
// many candidates). Verified during testing: several wrong XOR keys
// produced punctuation-heavy pseudo-text that scored HIGHER on the plain
// langdetect confidence than the correct key, because a handful of
// coincidental single-letter "word" matches inflated the ratio on
// short/fragmented tokenization.
//
// This requires the decoded text to actually consist of clean
// whitespace-separated words (letters only, plus at most one trailing
// punctuation mark like a comma or period) - not just contain letters
// somewhere.
func looksLikeRealSentence(s string) bool {
	tokens := strings.Fields(s)
	if len(tokens) < 4 {
		return false
	}
	clean := 0
	for _, t := range tokens {
		t = strings.TrimRight(t, ".,!?;:'\"")
		if len(t) < 2 {
			continue
		}
		isAlpha := true
		for _, r := range t {
			if !unicode.IsLetter(r) {
				isAlpha = false
				break
			}
		}
		if isAlpha {
			clean++
		}
	}
	return float64(clean)/float64(len(tokens)) >= 0.7
}

// validateCrackCandidate is the single gate every brute-force crack result
// (Caesar, Vigenère, XOR) must pass before being trusted. Layered checks,
// each added after a specific false positive was caught during testing:
//  1. Basic language-detection confidence.
//  2. looksLikeRealSentence - rejects punctuation-mixed word-salad that
//     inflates the stopword-fraction score.
//  3. For English/French specifically, where real corpus bigram data is
//     available (internal/ngram): require a minimum fraction of actual
//     recognized word-pairs, not just recognized single words. This is
//     the hardest check to fool by chance - a wrong key producing two
//     correct consecutive words in a row is far less likely than one.
//     Spanish/German don't have bigram data yet, so they skip this extra
//     layer and rely on checks 1-2 only - a real, disclosed asymmetry.
func validateCrackCandidate(plaintext string, lr langdetect.Result) bool {
	if lr.Language == "" || lr.Confidence < 0.20 {
		return false
	}
	if !looksLikeRealSentence(plaintext) {
		return false
	}
	if ngram.HasBigramData(lr.Language) {
		if ngram.PlausibilityScore(plaintext, lr.Language) < 0.12 {
			return false
		}
	}
	return true
}

// piiBoost is a small extra confidence bump for decoded plaintext that
// contains PII-shaped structure (emails, names, IDs, etc.), atop the
// primary language-based validation. It weights human-signal evidence
// less than word-frequency scoring, as it should.
func piiBoost(plaintext string) float64 {
	if piiDetector == nil {
		return 0
	}
	return piiDetector.DecodeTextScore(plaintext)
}

// capConfidence keeps confidence from exceeding a single-digit-percent
// ceiling (0.99) after the PII boost is added, so output like
// "confidence 101%" never happens.
func capConfidence(c float64) float64 {
	if c > 0.99 {
		return 0.99
	}
	if c < 0 {
		return 0
	}
	return c
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
