// internal/translate/translate.go
//
// Rough, mechanical, dictionary-based "translation": tokenize text in a
// given language, look each token up in that language's dictionary data,
// and present the gloss breakdown plus a naive assembled rendering (first
// definition of each token, joined). This is deliberately NOT machine
// translation - there's no grammar model, no reordering, no
// disambiguation between senses, no attempt at fluent output. It's the
// same category of tool as the classical-cipher decoder elsewhere in
// this package family: given a known "key" (here, dictionary data
// instead of a shift/Vigenère key), decode token-by-token and show your
// work. Treating an unfamiliar language as something to be "decoded" via
// a lookup table is a fair, honest description of what this actually
// does - it is not a claim of real translation quality.
package translate

import (
	"sort"
	"strings"
	"unicode"

	"compliancecheck/internal/langdata"
)

type Token struct {
	Text        string   `json:"text"`
	Definitions []string `json:"definitions,omitempty"`
	Pinyin      string   `json:"pinyin,omitempty"`
	Readings    string   `json:"readings,omitempty"`
	Found       bool     `json:"found"`
}

type Result struct {
	LanguageCode string  `json:"language_code"`
	LanguageName string  `json:"language_name"`
	Tokens       []Token `json:"tokens"`
	// RoughTranslation is the first definition of each found token, joined
	// with spaces - a crude, literal, word-order-preserving rendering, not
	// a fluent translation. Tokens with no dictionary match are skipped in
	// this line but still shown individually in Tokens.
	RoughTranslation string `json:"rough_translation"`
	// CoveragePct is the fraction of tokens that had a dictionary match -
	// low coverage is an honest signal that the rough translation below is
	// missing a lot, not a hidden caveat.
	CoveragePct float64 `json:"coverage_pct"`
}

// AutoMinCoverage is the dictionary-coverage floor an auto-selected gloss
// must clear for us to present it as a confident match. Below this, the
// text is treated as NOT plausibly any dictionary language, so the caller
// can keep saying "unrecognized" rather than showing a near-empty gloss.
const AutoMinCoverage = 0.5

// TranslateAuto tries every language that has dictionary data and returns
// the best-matching gloss for text. It is the "guess the language from the
// dictionary, not from stopwords" fallback: languages with segmented
// scripts (Chinese) or dense small vocabularies (Spanish) often score
// high coverage even when the stopword-based langdetect knows nothing
// about them. ok=false means no language cleared the coverage bar, i.e.
// the text is probably not any dictionary language at all.
func TranslateAuto(text string) (Result, bool) {
	codes := langdata.Codes()
	sort.Strings(codes) // deterministic final tie-break
	var best Result
	for _, code := range codes {
		lang, ok := langdata.Get(code)
		if !ok || !lang.HasDictionary() {
			continue
		}
		r, ok := Translate(text, code)
		if !ok {
			continue
		}
		if best.CoveragePct == 0 && len(best.Tokens) == 0 || betterGloss(r, best, text) {
			best = r
		}
	}
	if best.CoveragePct < AutoMinCoverage {
		return Result{}, false
	}
	return best, true
}

// betterGloss ranks two candidate glosses: higher coverage, then the
// segmentation that matched more tokens (a word-based split beats a
// per-character one), then the language whose script the text actually
// uses (resolves the Chinese/Japanese shared-Han ambiguity), then code
// order for a fully deterministic pick.
func betterGloss(a, b Result, text string) bool {
	if a.LanguageCode == b.LanguageCode {
		return false
	}
	if a.CoveragePct != b.CoveragePct {
		return a.CoveragePct > b.CoveragePct
	}
	if len(a.Tokens) != len(b.Tokens) {
		return len(a.Tokens) > len(b.Tokens)
	}
	if sa, sb := scriptBonus(a.LanguageCode, text), scriptBonus(b.LanguageCode, text); sa != sb {
		return sa > sb
	}
	return a.LanguageCode < b.LanguageCode
}

// scriptBonus slightly favors the language whose script the input uses.
// Japanese and Chinese share Han/kanji characters (逐玉 glosses fully in
// both), but kana strongly implies Japanese, and kana-free Han text more
// likely means Chinese, which is also usually the more complete dictionary
// for a bare CJK paste.
func scriptBonus(code, text string) int {
	hasHan := false
	hasKana := false
	for _, r := range text {
		switch {
		case r >= 0x4E00 && r <= 0x9FFF: // CJK Unified Ideographs
			hasHan = true
		case r >= 0x3040 && r <= 0x30FF: // Hiragana + Katakana
			hasKana = true
		}
	}
	switch code {
	case "ja":
		if hasKana {
			return 3
		}
		if hasHan {
			return 1
		}
	case "zh":
		if hasHan && !hasKana {
			return 2
		}
	case "es":
		if !hasHan && !hasKana {
			return 1
		}
	}
	return 0
}

// Translate tokenizes text according to the language's script conventions
// (CJK dictionary-segmentation for Chinese, per-kanji for Japanese,
// whitespace for everything else) and glosses each token.
func Translate(text, langCode string) (Result, bool) {
	lang, ok := langdata.Get(langCode)
	if !ok || !lang.HasDictionary() {
		return Result{}, false
	}

	var rawTokens []string
	switch langCode {
	case "zh":
		rawTokens = lang.SegmentCJK(text)
	case "ja":
		rawTokens = segmentByRune(text) // no compound-word dictionary for Japanese, only per-kanji (see package doc)
	default:
		rawTokens = strings.Fields(text)
	}

	var tokens []Token
	var roughParts []string
	found := 0
	total := 0
	for _, raw := range rawTokens {
		clean := strings.Trim(raw, ".,!?;:\"'()[]{}\u3002\uFF0C\uFF01\uFF1F\u3001") // include common CJK punctuation
		if clean == "" {
			continue
		}
		total++
		entry, ok := lang.Gloss(clean)
		tok := Token{Text: clean, Found: ok}
		if ok {
			found++
			tok.Definitions = entry.Definitions
			tok.Pinyin = entry.Pinyin
			tok.Readings = entry.Readings
			if len(entry.Definitions) > 0 {
				roughParts = append(roughParts, firstClause(entry.Definitions[0]))
			}
		}
		tokens = append(tokens, tok)
	}

	coverage := 0.0
	if total > 0 {
		coverage = float64(found) / float64(total)
	}

	return Result{
		LanguageCode:     langCode,
		LanguageName:     lang.Name,
		Tokens:           tokens,
		RoughTranslation: strings.Join(roughParts, " "),
		CoveragePct:      coverage,
	}, true
}

// segmentByRune splits into individual runes, skipping whitespace - the
// fallback for Japanese, which mixes kanji (coverable via the Jōyō
// dictionary) with hiragana/katakana grammatical particles that aren't in
// a kanji dictionary at all. This does NOT attempt real Japanese word
// segmentation (that needs a proper dictionary of multi-character words,
// which wasn't supplied - only single-kanji meanings were) - it's an
// honest per-character fallback, not a claim of word-level accuracy.
func segmentByRune(text string) []string {
	var out []string
	for _, r := range text {
		if unicode.IsSpace(r) {
			continue
		}
		out = append(out, string(r))
	}
	return out
}

// firstClause takes just the first semicolon/comma-delimited clause of a
// definition, for the rough-translation line - a full CEDICT definition
// like "of; ~'s (possessive particle)/(used after...)" is far too long to
// usefully sit inline in a reconstructed sentence.
func firstClause(def string) string {
	for _, sep := range []string{";", ","} {
		if i := strings.Index(def, sep); i > 0 && i < 40 {
			return strings.TrimSpace(def[:i])
		}
	}
	if len(def) > 40 {
		return strings.TrimSpace(def[:40])
	}
	return def
}
