// internal/cipher/more_encodings.go
//
// Additional encodings from the original FALIP spec's cipher list not yet
// covered: Morse code, Octal (ASCII codes in base 8), Decimal (ASCII codes
// in base 10), and Leetspeak (character substitution, not really an
// "encoding" in the reversible sense but detectable/reversible well enough
// to be useful forensically - e.g. "p4ssw0rd" in a file).
package cipher

import (
	"regexp"
	"strconv"
	"strings"
)

// --- Morse code ---

var morseTable = map[rune]string{
	'a': ".-", 'b': "-...", 'c': "-.-.", 'd': "-..", 'e': ".", 'f': "..-.",
	'g': "--.", 'h': "....", 'i': "..", 'j': ".---", 'k': "-.-", 'l': ".-..",
	'm': "--", 'n': "-.", 'o': "---", 'p': ".--.", 'q': "--.-", 'r': ".-.",
	's': "...", 't': "-", 'u': "..-", 'v': "...-", 'w': ".--", 'x': "-..-",
	'y': "-.--", 'z': "--..",
	'0': "-----", '1': ".----", '2': "..---", '3': "...--", '4': "....-",
	'5': ".....", '6': "-....", '7': "--...", '8': "---..", '9': "----.",
}

var morseReverse = func() map[string]rune {
	m := map[string]rune{}
	for r, code := range morseTable {
		m[code] = r
	}
	return m
}()

func MorseEncode(s string) string {
	var words []string
	for _, word := range strings.Fields(strings.ToLower(s)) {
		var letters []string
		for _, r := range word {
			if code, ok := morseTable[r]; ok {
				letters = append(letters, code)
			}
		}
		if len(letters) > 0 {
			words = append(words, strings.Join(letters, " "))
		}
	}
	return strings.Join(words, " / ")
}

func MorseDecode(s string) (string, error) {
	words := strings.Split(s, "/")
	var out []string
	matched := 0
	total := 0
	for _, word := range words {
		var letters []string
		for _, code := range strings.Fields(word) {
			total++
			if r, ok := morseReverse[code]; ok {
				letters = append(letters, string(r))
				matched++
			}
		}
		out = append(out, strings.Join(letters, ""))
	}
	if total == 0 || matched == 0 {
		return "", errDecodeFailed
	}
	return strings.Join(out, " "), nil
}

var morseCandidateRe = regexp.MustCompile(`(?:[.\-]{1,6}[ /]){2,}[.\-]{1,6}`)

// --- Octal (space-separated 3-digit ASCII codes, e.g. "150 145 154") ---

func OctalEncode(s string) string {
	var parts []string
	for _, b := range []byte(s) {
		parts = append(parts, strconv.FormatInt(int64(b), 8))
	}
	return strings.Join(parts, " ")
}

func OctalDecode(s string) (string, error) {
	return decodeNumericGroups(s, 8)
}

var octalCandidateRe = regexp.MustCompile(`\b(?:[0-7]{2,4}[ ]){3,}[0-7]{2,4}\b`)

// --- Decimal (space-separated ASCII codes, e.g. "104 101 108 108 111") ---

func DecimalEncode(s string) string {
	var parts []string
	for _, b := range []byte(s) {
		parts = append(parts, strconv.Itoa(int(b)))
	}
	return strings.Join(parts, " ")
}

func DecimalDecode(s string) (string, error) {
	return decodeNumericGroups(s, 10)
}

var decimalCandidateRe = regexp.MustCompile(`\b(?:\d{2,3}[ ]){3,}\d{2,3}\b`)

func decodeNumericGroups(s string, base int) (string, error) {
	groups := strings.Fields(s)
	if len(groups) == 0 {
		return "", errDecodeFailed
	}
	var out []byte
	for _, g := range groups {
		n, err := strconv.ParseInt(g, base, 32)
		if err != nil || n < 0 || n > 255 {
			return "", errDecodeFailed
		}
		out = append(out, byte(n))
	}
	return string(out), nil
}

// --- Leetspeak ---
//
// Not a real reversible cipher (many substitutions are ambiguous - '1' could
// be 'i' or 'l'), so this is detect + best-effort reverse, not a strict
// Decode. Common in forensic contexts for obfuscated profanity, credentials,
// or extremist/coded terminology in otherwise plain text.
var leetSubstitutions = map[rune]rune{
	'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's',
}

var leetForward = map[rune]rune{
	'o': '0', 'i': '1', 'e': '3', 'a': '4', 's': '5', 't': '7', 'b': '8',
}

// ToLeetspeak is a simple, common substitution set (the inverse of
// LeetspeakReverse's mapping) - not the only leetspeak convention in use,
// but a standard one.
func ToLeetspeak(s string) string {
	var b strings.Builder
	for _, r := range s {
		lower := r
		if r >= 'A' && r <= 'Z' {
			lower = r + ('a' - 'A')
		}
		if repl, ok := leetForward[lower]; ok {
			b.WriteRune(repl)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func LeetspeakReverse(s string) string {
	var b strings.Builder
	for _, r := range s {
		if repl, ok := leetSubstitutions[r]; ok {
			b.WriteRune(repl)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// LooksLikeLeetspeak is a light heuristic: a meaningful fraction of
// characters are leet-substitutable digits/symbols embedded within
// otherwise-alphabetic words (not e.g. a phone number or a price).
func LooksLikeLeetspeak(word string) bool {
	if len(word) < 3 {
		return false
	}
	letters, leetChars := 0, 0
	for _, r := range word {
		if _, ok := leetSubstitutions[r]; ok {
			leetChars++
		} else if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			letters++
		}
	}
	return leetChars > 0 && letters > 0 && leetChars <= letters
}
