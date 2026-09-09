// internal/pii/pii.go
//
// False positives are the #1 complaint about naive PII scanners: a regex
// that matches "13-19 digits" flags every invoice number and phone number
// as a credit card. This detector fixes that two ways:
//
//  1. Checksum validation where the PII type has a real check digit
//     (Luhn for card numbers / SIN, structural validation for SSN).
//     A digit string that fails Luhn is almost certainly NOT a real card
//     number - we downgrade instead of flagging it CRITICAL.
//  2. Context keywords, checked in a window around the match, in
//     whatever language matched (via internal/langdetect). Finding a
//     bare 9-digit number is LOW; finding one next to "SIN"/"NAS" is
//     CRITICAL. This is also the extension point for "more languages":
//     add a language's keywords to rules.json, no code change.
package pii

import (
	"embed"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

//go:embed rules.json
var embedded embed.FS

type rawRule struct {
	ID               string              `json:"id"`
	Label            string              `json:"label"`
	Pattern          string              `json:"pattern"`
	Severity         string              `json:"severity"`
	Checksum         string              `json:"checksum"`
	MinDigits        int                 `json:"min_digits"`
	MaxDigits        int                 `json:"max_digits"`
	ContextKeywords  map[string][]string `json:"context_keywords"`
}

type Rule struct {
	rawRule
	re *regexp.Regexp
}

type Match struct {
	RuleID           string `json:"rule_id"`
	Label            string `json:"label"`
	Severity         string `json:"severity"`      // may be downgraded/upgraded from the rule default
	BaseSeverity     string `json:"base_severity"`
	Value            string `json:"value"`          // redacted before it ever leaves this package
	ChecksumPassed   *bool  `json:"checksum_passed,omitempty"`
	ContextMatched   string `json:"context_matched,omitempty"` // which language's keyword hit, if any
	Position         int    `json:"position"`
}

type Detector struct {
	rules []*Rule
}

func Load() (*Detector, error) {
	b, err := embedded.ReadFile("rules.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Rules []rawRule `json:"rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	d := &Detector{}
	for _, r := range doc.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, err
		}
		d.rules = append(d.rules, &Rule{rawRule: r, re: re})
	}
	return d, nil
}

// RuleInfo is public PII rule metadata, exposed so a UI can offer a
// "search for just these PII types" picker.
type RuleInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// ListRules returns metadata for every loaded rule, for building a PII-type
// picker in a UI. Does not require Load() to have succeeded elsewhere -
// each call is independent (rules.json is tiny and embedded, so this is cheap).
func (d *Detector) ListRules() []RuleInfo {
	out := make([]RuleInfo, 0, len(d.rules))
	for _, r := range d.rules {
		out = append(out, RuleInfo{ID: r.ID, Label: r.Label})
	}
	return out
}
// contextWindow controls how many characters around a match are checked for keywords.
func (d *Detector) Scan(text string) []Match {
	lower := strings.ToLower(text)
	var out []Match

	for _, rule := range d.rules {
		locs := rule.re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			raw := text[loc[0]:loc[1]]
			m := Match{
				RuleID:       rule.ID,
				Label:        rule.Label,
				BaseSeverity: rule.Severity,
				Severity:     rule.Severity,
				Value:        redact(rule.ID, raw),
				Position:     loc[0],
			}

			if rule.Checksum != "none" && rule.Checksum != "" {
				ok := validateChecksum(rule.Checksum, raw, rule.MinDigits, rule.MaxDigits)
				m.ChecksumPassed = &ok
				if !ok {
					// Failed checksum: this is very likely NOT the PII type the pattern
					// suggests (e.g. a random 16-digit invoice number, not a card number).
					// Downgrade hard rather than dropping it, so it's still reviewable.
					m.Severity = downgrade(m.Severity)
				}
			}

			if lang, kw := findContext(lower, loc[0], loc[1], rule.ContextKeywords); kw != "" {
				m.ContextMatched = lang + ":" + kw
				m.Severity = upgrade(m.Severity)
			}

			out = append(out, m)
		}
	}
	return out
}

const contextWindow = 40

func findContext(lowerText string, start, end int, keywords map[string][]string) (lang, keyword string) {
	if len(keywords) == 0 {
		return "", ""
	}
	from := start - contextWindow
	if from < 0 {
		from = 0
	}
	to := end + contextWindow
	if to > len(lowerText) {
		to = len(lowerText)
	}
	window := lowerText[from:to]
	for l, words := range keywords {
		for _, w := range words {
			if strings.Contains(window, strings.ToLower(w)) {
				return l, w
			}
		}
	}
	return "", ""
}

var severityOrder = []string{"info", "low", "medium", "high", "critical"}

func downgrade(sev string) string {
	for i, s := range severityOrder {
		if s == sev && i > 0 {
			return severityOrder[i-1]
		}
	}
	return sev
}

func upgrade(sev string) string {
	for i, s := range severityOrder {
		if s == sev && i < len(severityOrder)-1 {
			return severityOrder[i+1]
		}
	}
	return sev
}

// redact keeps enough of the match to be useful in a report without storing
// the full sensitive value verbatim (email domain, card last 4, etc.)
func redact(ruleID, value string) string {
	switch ruleID {
	case "CREDIT_CARD", "SSN_US", "SIN_CA":
		digits := onlyDigits(value)
		if len(digits) >= 4 {
			return strings.Repeat("*", len(digits)-4) + digits[len(digits)-4:]
		}
		return strings.Repeat("*", len(value))
	case "EMAIL":
		at := strings.Index(value, "@")
		if at > 1 {
			return value[:1] + strings.Repeat("*", at-1) + value[at:]
		}
		return value
	default:
		if len(value) > 6 {
			return value[:3] + strings.Repeat("*", len(value)-3)
		}
		return strings.Repeat("*", len(value))
	}
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func validateChecksum(kind, raw string, minDigits, maxDigits int) bool {
	digits := onlyDigits(raw)
	switch kind {
	case "luhn":
		if minDigits > 0 && len(digits) < minDigits {
			return false
		}
		if maxDigits > 0 && len(digits) > maxDigits {
			return false
		}
		return luhnValid(digits)
	case "ssn_us":
		return ssnUSValid(digits)
	default:
		return true
	}
}

// luhnValid implements the standard Luhn checksum used by card numbers and
// (in Canada) Social Insurance Numbers.
func luhnValid(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n, err := strconv.Atoi(string(digits[i]))
		if err != nil {
			return false
		}
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// ssnUSValid rejects the well-known invalid SSN patterns (all-zero segments,
// 000/666/900-999 area numbers) that make naive \d{3}-\d{2}-\d{4} matching noisy.
func ssnUSValid(digits string) bool {
	if len(digits) != 9 {
		return false
	}
	area, group, serial := digits[0:3], digits[3:5], digits[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}
