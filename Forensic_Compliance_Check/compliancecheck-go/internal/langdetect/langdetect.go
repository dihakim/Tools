// internal/langdetect/langdetect.go
//
// Deliberately simple stopword-frequency detector rather than a heavy
// statistical model: the point is that adding a new language is a data
// change (drop a JSON file in internal/data/langfreq), not a code change.
// It also doubles as the "is this actually a known language, or is it
// gibberish/cipher text" signal: if nothing scores above the confidence
// floor, that's a real finding in its own right.
package langdetect

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"
)

//go:embed *.json
var embedded embed.FS

type langProfile struct {
	Language  string          `json:"language"`
	Name      string          `json:"name"`
	Stopwords map[string]bool `json:"-"`
	raw       []string
}

type Detector struct {
	profiles []*langProfile
}

var wordRe = regexp.MustCompile(`[\p{L}]+`)

func Load() (*Detector, error) {
	entries, err := embedded.ReadDir(".")
	if err != nil {
		return nil, err
	}
	d := &Detector{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := embedded.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		var p struct {
			Language  string   `json:"language"`
			Name      string   `json:"name"`
			Stopwords []string `json:"stopwords"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		lp := &langProfile{Language: p.Language, Name: p.Name, Stopwords: map[string]bool{}}
		for _, w := range p.Stopwords {
			lp.Stopwords[strings.ToLower(w)] = true
		}
		d.profiles = append(d.profiles, lp)
	}
	return d, nil
}

// Result of language detection for a chunk of text.
type Result struct {
	Language      string             `json:"language"`       // "" if no language scored above MinConfidence
	LanguageName  string             `json:"language_name"`
	Confidence    float64            `json:"confidence"`      // 0..1, fraction of tokens matching the winning language's stopwords
	Scores        map[string]float64 `json:"scores"`
	TokensChecked int                `json:"tokens_checked"`
}

// MinConfidence below this, we don't claim a language match at all -
// callers use that as a "possible cipher / unrecognized text" signal.
const MinConfidence = 0.08

func (d *Detector) Detect(text string) Result {
	tokens := wordRe.FindAllString(strings.ToLower(text), -1)
	res := Result{Scores: map[string]float64{}, TokensChecked: len(tokens)}
	if len(tokens) == 0 {
		return res
	}

	best := ""
	bestName := ""
	bestScore := -1.0
	for _, p := range d.profiles {
		hits := 0
		for _, t := range tokens {
			if p.Stopwords[t] {
				hits++
			}
		}
		score := float64(hits) / float64(len(tokens))
		res.Scores[p.Language] = score
		if score > bestScore {
			bestScore = score
			best = p.Language
			bestName = p.Name
		}
	}

	if bestScore >= MinConfidence {
		res.Language = best
		res.LanguageName = bestName
		res.Confidence = bestScore
	}
	return res
}
