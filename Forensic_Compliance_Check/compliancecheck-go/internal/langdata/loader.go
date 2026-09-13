// internal/langdata/loader.go
//
// Auto-discovers languages from data/<code>/{words,bigrams,sentences}.csv.
// Adding a language is dropping a new data/<code>/ directory with
// whichever of the three files you have - no Go code change. Adding a
// dataset to an existing language (e.g. words.csv for a language that
// currently only has bigrams.csv) is the same: drop the file in, the
// next build picks it up.
//
// CSV format for all three, header required:
//   words.csv:     text,popularity,risk       (risk optional, blank ok)
//   bigrams.csv:   text,popularity
//   sentences.csv: text,popularity
package langdata

import (
	"embed"
	"encoding/csv"
	"io/fs"
	"strconv"
	"strings"
)

//go:embed data
var embedded embed.FS

// languageNames maps a directory code to its display name. A code without
// an entry here still loads fine (Name falls back to the code itself) -
// this is just for nicer display, not a gate on which languages can exist.
var languageNames = map[string]string{
	"en": "English", "fr": "French", "es": "Spanish", "de": "German",
}

var registry = map[string]*Language{}

func init() {
	entries, err := fs.ReadDir(embedded, "data")
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		code := e.Name()
		name := languageNames[code]
		if name == "" {
			name = code
		}
		lang := newLanguage(code, name)
		loadCSVInto(lang, "data/"+code+"/words.csv", func(rec []string) {
			if len(rec) < 1 || rec[0] == "" {
				return
			}
			w := Word{Text: rec[0]}
			if len(rec) > 1 {
				w.Popularity, _ = strconv.Atoi(rec[1])
			}
			if len(rec) > 2 && rec[2] != "" {
				w.Risk, _ = strconv.ParseFloat(rec[2], 64)
			}
			lang.addWord(w)
		})
		loadCSVInto(lang, "data/"+code+"/bigrams.csv", func(rec []string) {
			if len(rec) < 1 || rec[0] == "" {
				return
			}
			b := Bigram{Text: strings.ToLower(rec[0])}
			if len(rec) > 1 {
				b.Popularity, _ = strconv.Atoi(rec[1])
			}
			lang.addBigram(b)
		})
		loadCSVInto(lang, "data/"+code+"/sentences.csv", func(rec []string) {
			if len(rec) < 1 || rec[0] == "" {
				return
			}
			s := Sentence{Text: rec[0]}
			if len(rec) > 1 {
				s.Popularity, _ = strconv.Atoi(rec[1])
			}
			lang.addSentence(s)
		})

		// Only register languages that actually have at least one dataset -
		// an empty directory shouldn't produce a phantom language entry.
		if lang.HasWords() || lang.HasBigrams() || lang.HasSentences() {
			registry[code] = lang
		}
	}
}

func loadCSVInto(lang *Language, path string, onRecord func(rec []string)) {
	f, err := embedded.Open(path)
	if err != nil {
		return // dataset not present for this language yet - not an error
	}
	defer f.Close()

	r := csv.NewReader(f)
	first := true
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if first {
			first = false
			continue // header row
		}
		onRecord(rec)
	}
}

// Get returns the Language for a code, if any data has been loaded for it.
func Get(code string) (*Language, bool) {
	l, ok := registry[code]
	return l, ok
}

// Codes returns every language code with at least one loaded dataset.
func Codes() []string {
	out := make([]string, 0, len(registry))
	for code := range registry {
		out = append(out, code)
	}
	return out
}
