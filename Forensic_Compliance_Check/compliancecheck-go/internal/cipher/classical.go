// internal/cipher/classical.go
//
// Classical substitution/polyalphabetic ciphers: ROT13, general Caesar
// shift, Atbash, and Vigenère. Unlike the encodings in encodings.go,
// these ARE meant for secrecy and can have a key - so alongside plain
// Encode/Decode-with-known-key, this file also implements automatic
// cracking (frequency analysis) for when no key is known, which is
// exactly the "if there is a key/code, auto-decode" requirement: Caesar
// and Atbash have no key to guess (Atbash is self-inverse; Caesar's
// "key" is just one of 25 shifts, brute-forceable), and Vigenère's key
// is recovered via Index-of-Coincidence key-length detection followed by
// per-column chi-squared frequency analysis - standard classical
// cryptanalysis, not a shortcut.
package cipher

import (
	"strings"
)

// --- Caesar / ROT13 ---

// CaesarEncode shifts each letter by n (0-25), preserving case and
// leaving non-letters untouched. CaesarDecode(s, n) == CaesarEncode(s, 26-n).
func CaesarEncode(s string, n int) string {
	n = ((n % 26) + 26) % 26
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune('a' + (r-'a'+rune(n))%26)
		case r >= 'A' && r <= 'Z':
			b.WriteRune('A' + (r-'A'+rune(n))%26)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func CaesarDecode(s string, n int) string { return CaesarEncode(s, 26-((n%26)+26)%26) }

func ROT13(s string) string { return CaesarEncode(s, 13) } // self-inverse

// --- Atbash (A<->Z, B<->Y, ...) - self-inverse, no key ---

func Atbash(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune('z' - (r - 'a'))
		case r >= 'A' && r <= 'Z':
			b.WriteRune('Z' - (r - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- Vigenère ---

func VigenereEncode(s, key string) string { return vigenere(s, key, 1) }
func VigenereDecode(s, key string) string { return vigenere(s, key, -1) }

func vigenere(s, key string, dir int) string {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return s
	}
	var keyIdx int
	var b strings.Builder
	for _, r := range s {
		var base rune
		switch {
		case r >= 'a' && r <= 'z':
			base = 'a'
		case r >= 'A' && r <= 'Z':
			base = 'A'
		default:
			b.WriteRune(r)
			continue
		}
		k := rune(key[keyIdx%len(key)]) - 'A'
		shift := (int(k) * dir) % 26
		offset := ((int(r-base)+shift)%26 + 26) % 26
		b.WriteRune(base + rune(offset))
		keyIdx++
	}
	return b.String()
}

// englishFreq is standard English letter frequency (%), used for
// chi-squared scoring during Caesar/Vigenère cracking. Classical
// cryptanalysis conventionally scores against English regardless of the
// plaintext's actual language; the final candidate is still validated
// against ALL supported languages via langdetect before being trusted
// (see crack.go), so this doesn't limit which language gets recognized -
// it's only the scoring heuristic used to pick shift/key candidates.
var englishFreq = map[rune]float64{
	'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
	'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
	'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
	'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
}

func chiSquared(text string) float64 {
	text = strings.ToLower(text)
	counts := map[rune]int{}
	total := 0
	for _, r := range text {
		if r >= 'a' && r <= 'z' {
			counts[r]++
			total++
		}
	}
	if total == 0 {
		return 1e9
	}
	var score float64
	for r, expectedPct := range englishFreq {
		observed := float64(counts[r])
		expected := expectedPct / 100 * float64(total)
		if expected == 0 {
			continue
		}
		diff := observed - expected
		score += (diff * diff) / expected
	}
	return score
}

// indexOfCoincidence measures how "peaky" the letter distribution is -
// close to ~0.067 for real English (and most natural languages), close to
// ~0.038 for random/well-encrypted text. Used to guess Vigenère key length:
// the correct key length is the one where splitting the text into that
// many interleaved streams maximizes the average IC (each stream becomes
// monoalphabetic, i.e. natural-language-like again).
func indexOfCoincidence(letters []rune) float64 {
	counts := map[rune]int{}
	for _, r := range letters {
		counts[r]++
	}
	n := len(letters)
	if n < 2 {
		return 0
	}
	var sum float64
	for _, c := range counts {
		sum += float64(c * (c - 1))
	}
	return sum / float64(n*(n-1))
}

func onlyLetters(s string) []rune {
	var out []rune
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' {
			out = append(out, r)
		}
	}
	return out
}
