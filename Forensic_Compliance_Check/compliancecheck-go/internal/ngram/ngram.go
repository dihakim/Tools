// internal/ngram/ngram.go
//
// Real bigram (word-pair) frequency data for English and French, sourced
// from actual corpus frequency lists. This exists specifically to fix a
// recurring class of bug: the classical-cipher-cracking validation in
// internal/cipher used a naive "fraction of tokens matching a stopword
// list" scorer, which proved exploitable during testing - garbled,
// wrong-key decode output could rack up coincidental single-word matches
// (a stray "a", "the", "y") and score HIGHER than the correct decode.
// Real bigrams are a much harder target to hit by chance: "of the" or
// "in the" appearing in wrong-key noise is far less likely than a single
// stopword appearing, because it requires TWO specific consecutive words
// to both be right.
//
// Coverage is asymmetric by design: English and French have real bigram
// data here (sourced from corpus frequency exports); Spanish and German
// don't, so cipher-crack validation for those two currently still relies
// solely on the lighter stopword-based check in internal/langdetect. This
// is a real, disclosed gap, not a secret limitation - Spanish/German
// crack results are therefore held to a slightly less rigorous bar than
// English/French ones until equivalent bigram data is sourced for them.
package ngram

import (
	"embed"
	"strings"
)

//go:embed en_bigrams.txt fr_bigrams.txt
var embedded embed.FS

var bigramSets = map[string]map[string]bool{}

func init() {
	for _, lang := range []string{"en", "fr"} {
		set := map[string]bool{}
		if b, err := embedded.ReadFile(lang + "_bigrams.txt"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					set[line] = true
				}
			}
		}
		bigramSets[lang] = set
	}
}

// HasBigramData reports whether real bigram data is available for a
// language code (currently "en" and "fr" only).
func HasBigramData(lang string) bool {
	set, ok := bigramSets[lang]
	return ok && len(set) > 0
}

// PlausibilityScore returns the fraction of consecutive word-pairs in text
// that are known real bigrams for the given language. 0 if the language
// isn't covered (check HasBigramData first) or the text is too short to
// form any word pairs.
func PlausibilityScore(text, lang string) float64 {
	set, ok := bigramSets[lang]
	if !ok || len(set) == 0 {
		return 0
	}
	words := tokenize(text)
	if len(words) < 2 {
		return 0
	}
	hits := 0
	pairs := 0
	for i := 0; i < len(words)-1; i++ {
		pairs++
		if set[words[i]+" "+words[i+1]] {
			hits++
		}
	}
	if pairs == 0 {
		return 0
	}
	return float64(hits) / float64(pairs)
}

func tokenize(text string) []string {
	text = strings.ToLower(text)
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '\'' {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return words
}
