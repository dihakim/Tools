// internal/cipher/transposition.go
//
// Transposition ciphers: Rail Fence, Scytale, and Columnar. Unlike the
// substitution ciphers elsewhere in this package, these rearrange the
// positions of characters without changing which characters there are -
// which inverts the detection problem: ciphertext and plaintext share the
// exact same letter frequency, so the usual chi-squared/stopword tests
// cannot tell a correct decode from a wrong one. What a transposition
// DOES destroy is the letter order, i.e. the *bigram* (letter-pair)
// distribution. English has a heavily skewed digraph distribution
// (TH/HE/IN/ER/AN alone are ~10% of all pairs), so a correct decode reads
// as strongly "English-shaped" at the digraph level while every wrong key
// produces essentially scrambled pairs. That powers the auto-solve below:
// brute-force candidate keys, score each decode by digraph chi-squared,
// pick the best, and only claim a crack when it's both a good fit and
// clearly better than every other key tried.
//
// All three strip to uppercase letters+digits (matching the reference
// Python implementation's _clean_text) and pad short last blocks with X,
// so plaintext spaces/punctuation are not recoverable from the ciphertext
// alone - the best a decode can return is the cleaned block.
package cipher

import (
	"sort"
	"strconv"
	"strings"

	"compliancecheck/internal/langdata"
	"compliancecheck/internal/langdetect"
)

// cleanUppercaseLetters mirrors the Python transposition base's _clean_text:
// keep alphanumerics, uppercase, drop everything else (spaces, punctuation).
func cleanUppercaseLetters(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- Rail Fence (zigzag across N rails, read off row by row) ---

// railFencePattern returns, for each plaintext position, which rail it
// lands on when the plaintext is written in a zigzag across `rails` rows.
func railFencePattern(length, rails int) []int {
	if rails < 2 {
		rails = 2
	}
	pattern := make([]int, length)
	rail, dir := 0, 1
	for i := 0; i < length; i++ {
		pattern[i] = rail
		rail += dir
		if rail == rails-1 || rail == 0 {
			dir = -dir
		}
	}
	return pattern
}

func RailFenceEncode(s string, rails int) string {
	if rails < 2 {
		return s
	}
	text := cleanUppercaseLetters(s)
	pattern := railFencePattern(len(text), rails)
	grid := make([][]byte, rails)
	for i, r := range text {
		grid[pattern[i]] = append(grid[pattern[i]], byte(r))
	}
	var b strings.Builder
	for _, rail := range grid {
		b.Write(rail)
	}
	return b.String()
}

func RailFenceDecode(s string, rails int) string {
	if rails < 2 {
		return s
	}
	text := cleanUppercaseLetters(s)
	pattern := railFencePattern(len(text), rails)
	// Order the rail positions (rail, column) the same way the encoder read
	// them back out; the ciphertext fills exactly those slots in that order.
	order := make([]int, len(pattern))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		pa, pb := pattern[order[a]], pattern[order[b]]
		if pa != pb {
			return pa < pb
		}
		return order[a] < order[b]
	})
	rebuilt := make([]byte, len(text))
	for i, pos := range order {
		rebuilt[pos] = text[i]
	}
	return string(rebuilt)
}

// --- Scytale (write along a rod of fixed diameter, read down the columns) ---

func ScytaleEncode(s string, diameter int) string {
	if diameter < 1 {
		return s
	}
	text := cleanUppercaseLetters(s)
	rows := (len(text) + diameter - 1) / diameter
	padded := padTo(text, rows*diameter, 'X')
	var b strings.Builder
	for col := 0; col < diameter; col++ {
		for row := 0; row < rows; row++ {
			b.WriteByte(padded[row*diameter+col])
		}
	}
	return b.String()
}

func ScytaleDecode(s string, diameter int) string {
	if diameter < 1 {
		return s
	}
	text := cleanUppercaseLetters(s)
	rows := (len(text) + diameter - 1) / diameter
	padded := padTo(text, rows*diameter, 'X')
	rebuilt := make([]byte, len(padded))
	idx := 0
	for col := 0; col < diameter; col++ {
		for row := 0; row < rows; row++ {
			rebuilt[row*diameter+col] = padded[idx]
			idx++
		}
	}
	return strings.TrimRight(string(rebuilt), "X")
}

// --- Columnar (write into rows, read columns in key order) ---

// columnarColOrder returns the order columns are read in: the columns of
// an alphabetic keyword sorted by their letters (stable, so equal letters
// keep left-to-right order), or the same sort applied to a numeric key
// like "321" (i.e. reversed) - digits work exactly like keyword letters,
// each column's character is its rank. Mixed keys sort digits before
// letters, which is the natural byte/sort order and is fine in practice.
func columnarColOrder(key string) []int {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return nil
	}
	// De-duplicate repeated characters while preserving first occurrence
	// (matches the reference implementation: a keyword with repeats is
	// collapsed before deriving the order).
	var seen [128]bool
	var chars []rune
	for _, r := range upper {
		if r < 128 && !seen[r] {
			seen[r] = true
			chars = append(chars, r)
		}
	}
	order := make([]int, len(chars))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return chars[order[a]] < chars[order[b]] })
	return order
}

func ColumnarEncode(s, key string) string {
	order := columnarColOrder(key)
	if len(order) == 0 {
		return s
	}
	text := cleanUppercaseLetters(s)
	cols := len(order)
	rows := (len(text) + cols - 1) / cols
	padded := padTo(text, rows*cols, 'X')
	var b strings.Builder
	for _, col := range order {
		for row := 0; row < rows; row++ {
			b.WriteByte(padded[row*cols+col])
		}
	}
	return b.String()
}

func ColumnarDecode(s, key string) string {
	order := columnarColOrder(key)
	if len(order) == 0 {
		return s
	}
	text := cleanUppercaseLetters(s)
	cols := len(order)
	rows := (len(text) + cols - 1) / cols
	padded := padTo(text, rows*cols, 'X')
	rebuilt := make([]byte, len(padded))
	idx := 0
	for _, col := range order {
		for row := 0; row < rows; row++ {
			rebuilt[row*cols+col] = padded[idx]
			idx++
		}
	}
	return strings.TrimRight(string(rebuilt), "X")
}

func padTo(s string, size int, pad byte) string {
	if len(s) >= size {
		return s
	}
	return s + strings.Repeat(string(pad), size-len(s))
}

// --- English digraph scoring + validation ---

// englishDigraphFreq is the relative frequency of each English letter-pair
// per 10,000 digraphs (approximate, standard cryptanalysis data). Only the
// common pairs are enumerated; pairs absent from the table score a small
// floor, which is what lets the chi-squared below treat an unusual pair as
// "knowingly rare rather than expected-but-missing."
var englishDigraphFreq = map[string]float64{
	"th": 307, "he": 269, "in": 225, "er": 204, "an": 197, "re": 171, "on": 159,
	"at": 147, "en": 144, "nd": 139, "ti": 138, "es": 134, "or": 131, "te": 128,
	"of": 125, "ed": 120, "is": 116, "it": 113, "al": 110, "ar": 108, "st": 105,
	"to": 104, "nt": 102, "ng": 99, "se": 98, "ha": 98, "as": 96, "ou": 94,
	"io": 91, "le": 89, "ve": 87, "co": 86, "me": 84, "de": 82, "hi": 80,
	"ri": 79, "ro": 79, "ic": 78, "ne": 76, "ea": 74, "ra": 73, "ce": 72,
	"li": 71, "ch": 69, "ll": 68, "be": 67, "ma": 66, "si": 65, "om": 64,
	"ur": 63, "ca": 62, "el": 61, "ta": 60, "la": 59, "ns": 58, "di": 58,
	"fo": 58, "ho": 57, "pe": 57, "ec": 56, "pr": 56, "no": 55, "ct": 55,
	"us": 55, "ac": 52, "od": 51, "cc": 51, "tr": 50, "il": 50, "ly": 50,
	"nc": 49, "ut": 49, "ru": 48, "em": 48, "lu": 47, "bo": 47, "yo": 46,
	"so": 46, "op": 45, "na": 43, "pa": 42, "do": 41, "im": 40, "ba": 40,
	"wa": 39, "ge": 39, "sa": 38, "sl": 38, "cr": 37, "su": 37, "sp": 37,
	"fi": 35, "cl": 35, "ft": 33, "oi": 33, "am": 32, "ry": 31, "mt": 29,
	"tt": 29, "wh": 29, "id": 28, "wn": 27, "ke": 27, "da": 27, "rd": 26,
	"pl": 26, "fe": 25, "ds": 25, "pi": 25, "gr": 25, "ck": 25, "wr": 25,
	"nf": 25, "mp": 24, "po": 24, "um": 24, "mu": 24, "ap": 24, "ay": 24,
	"gh": 24, "gl": 23, "ia": 23, "ty": 23, "ss": 23, "ad": 22, "lo": 22,
	"sh": 22, "vi": 22, "ko": 21, "mo": 44, "wo": 43,
}

// digraphChiSquared scores how English-like the letter-pair sequence of a
// cleaned transposition candidate is. Lower = more English-shaped. Only
// adjacent letter-letter pairs count (digits/punct break the stream, since
// the reference table is letters-only); word boundaries are invisible in
// cleaned text, so their spurious digraphs are necessarily included - which
// slightly penalizes ALL candidates equally and doesn't change ranking.
func digraphChiSquared(text string) float64 {
	lower := strings.ToLower(text)
	total := 0
	counts := map[string]int{}
	runes := []rune(lower)
	for i := 0; i+1 < len(runes); i++ {
		if runes[i] >= 'a' && runes[i] <= 'z' && runes[i+1] >= 'a' && runes[i+1] <= 'z' {
			counts[string(runes[i:i+2])]++
			total++
		}
	}
	if total < 8 {
		return 1e9 // too few digraphs to say anything - treat as non-English
	}
	var score float64
	for pair, observed := range counts {
		expected := 0.8 / 10000 * float64(total) // floor for pairs without data
		if ref, ok := englishDigraphFreq[pair]; ok {
			expected = ref / 10000 * float64(total)
		}
		diff := float64(observed) - expected
		score += (diff * diff) / expected
	}
	return score
}

// validateTranspositionCandidate gates an auto-solved transposition decode.
// A transposition is only convincingly solved when the winner is (a) a
// clear outlier from the field by digraph score (a wrong key leaves the
// letters in a scrambled order that scores like shuffled text), (b) reads
// as actual words - dictionary coverage well above the field's median
// (digraph score alone proved too flat near the bottom: a wrong columnar
// key can score within 0.2% of the true decode, because both draw the
// same letter-multiset's digraphs), and (c) long enough to say anything.
func validateTranspositionCandidate(winner transpositionCandidate, fieldMean, medianCover float64) bool {
	letters := cleanUppercaseLetters(winner.text)
	if len(letters) < 20 {
		return false
	}
	if fieldMean <= winner.score || winner.score > fieldMean*0.9 {
		return false
	}
	if winner.cover < 0.25 {
		return false
	}
	if medianCover > 0 && winner.cover < medianCover*2.0 {
		return false
	}
	return true
}

type transpositionCandidate struct {
	text  string
	key   string
	score float64 // digraph chi-squared, lower = more English-shaped
	cover float64 // fraction of letters covered by known dictionary words
}

// scoreTranspositionCandidates tries every candidate key via decode and
// scores each one two ways: digraph chi-squared (English-shaped letter
// order) and dictionary coverage (fraction of letters tileable into known
// words). Candidates that decode to empty are dropped.
func scoreTranspositionCandidates(text string, keys []string, decode func(string, string) string) []transpositionCandidate {
	var out []transpositionCandidate
	for _, k := range keys {
		decoded := decode(text, k)
		if strings.TrimSpace(decoded) == "" {
			continue
		}
		out = append(out, transpositionCandidate{
			text: decoded, key: k,
			score: digraphChiSquared(decoded),
			cover: dictionaryCoverage(decoded),
		})
	}
	return out
}

// pickTranspositionWinner ranks candidates by digraph score, then breaks
// ties among the plausible cluster by dictionary coverage: the true decode
// reads as words, a wrong-but-similar-scoring one does not. Returns the
// winner, the mean digraph score of the rest of the field, and the median
// dictionary coverage of the field (both needed by the validation gate).
func pickTranspositionWinner(cands []transpositionCandidate) (winner transpositionCandidate, fieldMean, medianCover float64, ok bool) {
	if len(cands) == 0 {
		return winner, 0, 0, false
	}
	sort.Slice(cands, func(a, b int) bool { return cands[a].score < cands[b].score })
	// The "plausible cluster" = best + anything within 50% worse, which
	// covers ties at the bottom of the score surface (see the gate comment).
	cutoff := cands[0].score * 1.5
	clusterEnd := 1
	for clusterEnd < len(cands) && cands[clusterEnd].score < cutoff {
		clusterEnd++
	}
	best := cands[0]
	for _, c := range cands[1:clusterEnd] {
		if c.cover > best.cover {
			best = c
		}
	}
	var sum float64
	for _, c := range cands {
		sum += c.score
	}
	fieldMean = (sum - best.score) / float64(len(cands)-1)
	covers := make([]float64, 0, len(cands))
	for _, c := range cands {
		covers = append(covers, c.cover)
	}
	sort.Float64s(covers)
	medianCover = covers[len(covers)/2]
	return best, fieldMean, medianCover, true
}

// dictionaryCoverage returns the fraction of a candidate's letters that can
// be tiled by known words in any language that ships word data (en/fr/es),
// via dynamic programming word segmentation - the "is this actually
// readable" signal for space-free text, which langdetect (stopword-based)
// can't provide since it tokenizes a solid letter-run as a single word.
//
// Only words of length >= 4 count. Shorter words proved useless as a
// discriminator: the three languages' 2-3 letter words tile ALMOST ANY
// letter string (a wrong columnar decode measured 0.70 coverage with
// length>=2, vs 0.80 for the true decode - no separation), whereas
// length>=4 real words require genuine word-forming order (true 0.80,
// wrong decode 0.29, pure scramble 0.00).
func dictionaryCoverage(text string) float64 {
	runes := []rune(strings.ToLower(cleanUppercaseLetters(text)))
	n := len(runes)
	if n < 8 {
		return 0
	}
	isWord := func(start, length int) bool {
		if start+length > n {
			return false
		}
		candidate := string(runes[start : start+length])
		for _, code := range []string{"en", "fr", "es"} {
			if l, ok := langdata.Get(code); ok {
				if _, ok := l.Word(candidate); ok {
					return true
				}
			}
		}
		return false
	}
	dp := make([]int, n+1)
	for i := range dp {
		dp[i] = -1
	}
	dp[0] = 0
	for i := 0; i < n; i++ {
		if dp[i] < 0 {
			continue
		}
		if dp[i] > dp[i+1] {
			dp[i+1] = dp[i] // this letter can stay uncovered
		}
		for length := 4; length <= 12 && i+length <= n; length++ {
			if isWord(i, length) && dp[i]+length > dp[i+length] {
				dp[i+length] = dp[i] + length
			}
		}
	}
	return float64(dp[n]) / float64(n)
}

// ---- Auto-solve (no key given) ----

// crackTranspositionResult packages a validated winner as a CrackResult.
// Confidence is derived from how far the winner stood out from the field
// (the digraph-outlier ratio), scaled so a clear solve (3x better than the
// field) tops out near 1 and a marginal one lands low. This is not a
// langdetect confidence and shouldn't be compared numerically with the
// substitution-cipher cracks that use one.
func crackTranspositionResult(method string, winner transpositionCandidate, fieldMean float64) CrackResult {
	conf := (fieldMean/winner.score - 1) / 3
	if conf > 1 {
		conf = 1
	}
	if conf < 0.05 {
		conf = 0.05
	}
	return CrackResult{Method: method, Key: winner.key, Plaintext: winner.text, Confidence: conf}
}

// CrackRailFence brute-forces rail counts 2..20 (the reference
// implementation's limit) and returns the best key that passes the
// transposition gate.
func CrackRailFence(text string, det *langdetect.Detector) (CrackResult, bool) {
	decoder := func(ciphertext, key string) string {
		n, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil {
			return ""
		}
		return RailFenceDecode(ciphertext, n)
	}
	var keys []string
	for rails := 2; rails <= 20; rails++ {
		keys = append(keys, strconv.Itoa(rails))
	}
	winner, fieldMean, medianCover, ok := pickTranspositionWinner(scoreTranspositionCandidates(text, keys, decoder))
	if !ok || !validateTranspositionCandidate(winner, fieldMean, medianCover) {
		return CrackResult{}, false
	}
	return crackTranspositionResult("railfence", winner, fieldMean), true
}

// CrackScytale brute-forces rod diameters 2..min(20, len) - a diameter
// >= len just leaves the text in place, so it's a no-op key.
func CrackScytale(text string, det *langdetect.Detector) (CrackResult, bool) {
	letters := cleanUppercaseLetters(text)
	maxDiameter := len(letters)
	if maxDiameter > 20 {
		maxDiameter = 20
	}
	decoder := func(ciphertext, key string) string {
		n, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil {
			return ""
		}
		return ScytaleDecode(ciphertext, n)
	}
	var keys []string
	for d := 2; d <= maxDiameter; d++ {
		keys = append(keys, strconv.Itoa(d))
	}
	winner, fieldMean, medianCover, ok := pickTranspositionWinner(scoreTranspositionCandidates(text, keys, decoder))
	if !ok || !validateTranspositionCandidate(winner, fieldMean, medianCover) {
		return CrackResult{}, false
	}
	return crackTranspositionResult("scytale", winner, fieldMean), true
}

// columnarTryKeys is the candidate key set for columnar auto-solve: the
// reference implementation's short common keys plus every numeric
// permutation of lengths 2..5 (a columnar key's real content is the column
// ORDER, so any ordering of N columns is a valid key - numeric keys make
// that brute-forceable directly rather than through letters).
func columnarTryKeys() []string {
	keys := []string{
		"KEY", "CODE", "SECRET", "PASSWORD", "CRYPTO", "ENCRYPT",
		"ALPHA", "ZEBRA", "ROYAL", "MATRIX", "CIPHER", "SIMPLE",
		"ABCD", "XYZ", "CBA",
	}
	for n := 2; n <= 5; n++ {
		digits := "123456789"[:n]
		var perms []string
		permuteDigits([]rune(digits), 0, &perms)
		keys = append(keys, perms...)
	}
	return keys
}

func permuteDigits(r []rune, start int, out *[]string) {
	if start == len(r) {
		*out = append(*out, string(r))
		return
	}
	seen := map[rune]bool{}
	for i := start; i < len(r); i++ {
		if seen[r[i]] {
			continue
		}
		seen[r[i]] = true
		r[start], r[i] = r[i], r[start]
		permuteDigits(r, start+1, out)
		r[start], r[i] = r[i], r[start]
	}
}

// CrackColumnar tries a fixed keyword list plus numeric permutations and
// returns the best key that passes the transposition gate.
func CrackColumnar(text string, det *langdetect.Detector) (CrackResult, bool) {
	decoder := func(ciphertext, key string) string {
		return ColumnarDecode(ciphertext, key)
	}
	winner, fieldMean, medianCover, ok := pickTranspositionWinner(scoreTranspositionCandidates(text, columnarTryKeys(), decoder))
	if !ok || !validateTranspositionCandidate(winner, fieldMean, medianCover) {
		return CrackResult{}, false
	}
	return crackTranspositionResult("columnar", winner, fieldMean), true
}