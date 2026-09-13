// internal/pii/customsearch.go
//
// User-directed search: "find every mention of this specific person" or
// "find every occurrence of this specific string/pattern" - distinct from
// the general PII detection engine (which finds ANY PII of a known type)
// and from the dictionary-based person-name detector (which finds ANY
// plausible name pair). This is targeted: given name components for one
// particular person, generate the realistic ways that name actually shows
// up in real documents - not just the one exact spelling the user typed.
package pii

import (
	"fmt"
	"regexp"
	"strings"
)

// NameQuery is what the user supplies: any subset of first/middle/last.
type NameQuery struct {
	First  string `json:"first"`
	Middle string `json:"middle"`
	Last   string `json:"last"`
}

// NameVariant is one generated search pattern plus how confident a hit
// on it actually identifies this person - "Mike Hawk Brown" is a strong
// signal, "M. Brown" alone is common enough to need lower confidence.
type NameVariant struct {
	Label      string
	Pattern    *regexp.Regexp
	Confidence string // "high" | "medium" | "low"
}

// GenerateNameVariants builds every realistic way a name could appear in
// text from the given components. Only components actually supplied are
// used - a bare first+last generates fewer variants than a full
// first+middle+last, since there's nothing to abbreviate that wasn't given.
func GenerateNameVariants(q NameQuery) ([]NameVariant, error) {
	first := strings.TrimSpace(q.First)
	middle := strings.TrimSpace(q.Middle)
	last := strings.TrimSpace(q.Last)
	if first == "" && last == "" {
		return nil, fmt.Errorf("need at least a first or last name to search for")
	}

	firstInit := initial(first)
	middleInit := initial(middle)

	type spec struct {
		label      string
		text       string
		confidence string
	}
	var specs []spec

	add := func(label, text, confidence string) {
		if text == "" {
			return
		}
		specs = append(specs, spec{label, text, confidence})
	}

	// Full combinations - highest confidence, most specific.
	if first != "" && middle != "" && last != "" {
		add("First Middle Last", first+" "+middle+" "+last, "high")
		add("First M. Last", first+" "+middleInit+". "+last, "high")
		add("Last, First Middle", last+", "+first+" "+middle, "high")
		add("Last, First M.", last+", "+first+" "+middleInit+".", "high")
	}
	if first != "" && last != "" {
		add("First Last", first+" "+last, "high")
		add("Last, First", last+", "+first, "high")
		add("F. Last", firstInit+". "+last, "medium")
		add("Last, F.", last+", "+firstInit+".", "medium")
		add("First L.", first+" "+lastInitialDot(last), "low")
	}
	// Single-component fallbacks - lowest confidence (common words alone),
	// but still generated since the user explicitly asked for this coverage.
	if first != "" && last == "" {
		add("First only", first, "low")
	}
	if last != "" && first == "" {
		add("Last only", last, "low")
	}

	var out []NameVariant
	seen := map[string]bool{}
	for _, s := range specs {
		if seen[s.text] {
			continue
		}
		seen[s.text] = true
		pattern, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(s.text) + `\b`)
		if err != nil {
			continue
		}
		out = append(out, NameVariant{Label: s.label, Pattern: pattern, Confidence: s.confidence})
	}
	return out, nil
}

func initial(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return string([]rune(s)[0])
}

func lastInitialDot(last string) string {
	i := initial(last)
	if i == "" {
		return ""
	}
	return i + "."
}

// NameMatchResult is one hit against a generated variant.
type NameMatchResult struct {
	VariantLabel string `json:"variant_label"`
	Confidence   string `json:"confidence"`
	MatchedText  string `json:"matched_text"`
	Position     int    `json:"position"`
}

// SearchNameVariants runs every generated variant against text, then keeps
// only the longest match at each starting position (a short variant like
// "Last, First" and a longer one like "Last, First Middle" can both match
// the same spot in text - the longer, more specific match is strictly more
// informative, so the shorter one there is just noise).
func SearchNameVariants(text string, variants []NameVariant) []NameMatchResult {
	var all []NameMatchResult
	for _, v := range variants {
		for _, loc := range v.Pattern.FindAllStringIndex(text, -1) {
			all = append(all, NameMatchResult{
				VariantLabel: v.Label,
				Confidence:   v.Confidence,
				MatchedText:  text[loc[0]:loc[1]],
				Position:     loc[0],
			})
		}
	}

	bestAtPosition := map[int]NameMatchResult{}
	for _, m := range all {
		existing, ok := bestAtPosition[m.Position]
		if !ok || len(m.MatchedText) > len(existing.MatchedText) {
			bestAtPosition[m.Position] = m
		}
	}

	out := make([]NameMatchResult, 0, len(bestAtPosition))
	for _, m := range bestAtPosition {
		out = append(out, m)
	}
	return out
}

// TermQuery is a user-supplied plain-string or regex search term.
type TermQuery struct {
	Text          string `json:"text"`
	IsRegex       bool   `json:"is_regex"`
	CaseSensitive bool   `json:"case_sensitive"`
}

// Compile turns a TermQuery into a ready-to-use regexp. Plain (non-regex)
// terms are escaped so user input can never be misinterpreted as regex
// syntax they didn't intend.
func (q TermQuery) Compile() (*regexp.Regexp, error) {
	pattern := q.Text
	if !q.IsRegex {
		pattern = regexp.QuoteMeta(pattern)
	}
	if !q.CaseSensitive {
		pattern = "(?i)" + pattern
	}
	return regexp.Compile(pattern)
}

type TermMatchResult struct {
	MatchedText string `json:"matched_text"`
	Position    int    `json:"position"`
}

func SearchTerm(text string, re *regexp.Regexp) []TermMatchResult {
	var out []TermMatchResult
	for _, loc := range re.FindAllStringIndex(text, -1) {
		out = append(out, TermMatchResult{MatchedText: text[loc[0]:loc[1]], Position: loc[0]})
	}
	return out
}
