// internal/pii/names.go
//
// Person-name detection via forename+surname dictionaries (sourced from a
// real international name-frequency dataset - ASCII/Latin-script entries
// only, ~1,240 forenames and ~1,500 surnames across many countries).
//
// This is NOT a regex rule like the others in rules.json, because names
// aren't a pattern - they're a vocabulary lookup. The key design choice
// for keeping false positives manageable: require an ADJACENT pair (a
// capitalized word matching the forename list immediately followed by one
// matching the surname list), not either list alone. A single common
// first name ("Grant", "Mark") or surname match alone would fire
// constantly in ordinary prose; requiring both halves of a plausible
// "First Last" pattern in sequence is a much sharper signal.
//
// This is inherently a coverage snapshot, not exhaustive - many real
// names (especially outside the ~1,200/1,500 most internationally common)
// won't be recognized, and this only covers Latin-script romanized forms.
package pii

import (
	"embed"
	"regexp"
	"strings"
)

//go:embed forenames.txt surnames.txt
var namesFS embed.FS

var forenameSet map[string]bool
var surnameSet map[string]bool

func init() {
	forenameSet = loadNameSet("forenames.txt")
	surnameSet = loadNameSet("surnames.txt")
}

func loadNameSet(filename string) map[string]bool {
	set := map[string]bool{}
	b, err := namesFS.ReadFile(filename)
	if err != nil {
		return set
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[strings.ToLower(line)] = true
		}
	}
	return set
}

// namePairRe finds "Capitalized Capitalized" two-word sequences - the
// candidate shape for a first+last name, before dictionary validation.
var namePairRe = regexp.MustCompile(`\b[A-Z][a-z]+ [A-Z][a-z]+\b`)

type NameMatch struct {
	Forename string
	Surname  string
	Position int
}

// DetectNames finds candidate "First Last" pairs where both words are
// recognized in the respective dictionaries.
func DetectNames(text string) []NameMatch {
	var out []NameMatch
	for _, loc := range namePairRe.FindAllStringIndex(text, -1) {
		pair := text[loc[0]:loc[1]]
		parts := strings.SplitN(pair, " ", 2)
		if len(parts) != 2 {
			continue
		}
		fore, sur := strings.ToLower(parts[0]), strings.ToLower(parts[1])
		if forenameSet[fore] && surnameSet[sur] {
			out = append(out, NameMatch{Forename: parts[0], Surname: parts[1], Position: loc[0]})
		}
	}
	return out
}

// MatchNames converts detected name pairs into PII Match entries so names
// flow through the SAME reporting channel as the regex rules (decode output,
// analyze results, UI rendering). The rule ID is PERSON_NAME, matching the
// entry ListRules adds to the PII-type picker. Value is kept readable - a
// name prompt isn't a credential, and redacting it would hide exactly what
// the user asked to be told about.
func MatchNames(text string) []Match {
	pairs := DetectNames(text)
	if len(pairs) == 0 {
		return nil
	}
	out := make([]Match, 0, len(pairs))
	for _, n := range pairs {
		out = append(out, Match{
			RuleID:       "PERSON_NAME",
			Label:        "Person name",
			Severity:     "high",
			BaseSeverity: "high",
			Importance:   80,
			Description:  "Person name (first + last name pair)",
			Value:        n.Forename + " " + n.Surname,
			Position:     n.Position,
		})
	}
	return out
}
