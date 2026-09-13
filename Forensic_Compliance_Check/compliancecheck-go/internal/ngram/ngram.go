// internal/ngram/ngram.go
//
// This package is now a thin compatibility wrapper. The actual bigram
// data (and the words/sentences data arriving alongside it) lives in
// internal/langdata's unified Language model - see that package's doc
// comment for the full design rationale. This wrapper exists so
// internal/cipher (which was written against this package's original
// HasBigramData/PlausibilityScore functions) didn't need to change when
// the underlying data model was unified - callers here are unaffected by
// how the data is organized underneath.
//
// New code should probably call internal/langdata directly rather than
// through this wrapper, since it exposes words and sentences too, not
// just bigrams.
package ngram

import "compliancecheck/internal/langdata"

// HasBigramData reports whether real bigram data is available for a
// language code (currently "en" and "fr").
func HasBigramData(lang string) bool {
	l, ok := langdata.Get(lang)
	return ok && l.HasBigrams()
}

// PlausibilityScore returns the fraction of consecutive word-pairs in text
// that are known real bigrams for the given language. 0 if the language
// isn't covered or the text is too short to form any word pairs.
func PlausibilityScore(text, lang string) float64 {
	l, ok := langdata.Get(lang)
	if !ok {
		return 0
	}
	return l.BigramPlausibility(text)
}
