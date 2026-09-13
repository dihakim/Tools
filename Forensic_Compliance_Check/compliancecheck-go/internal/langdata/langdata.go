// internal/langdata/langdata.go
//
// One place for everything known about a language: words, bigrams, and
// sentences. Design choice, and why: these three datasets arrive from
// different sources at different times (bigrams today, ~3000 words and
// sentences later per Diana's plan) and serve different purposes (word
// popularity/risk scoring, bigram plausibility for cipher-crack
// validation, sentence-level frequency data). Rather than nest them - a
// Bigram struct literally containing two Word structs, a Sentence
// containing its constituent Bigrams - each is a flat, independent
// collection, and "Foo references Bar" is a lookup method
// (bigram.FirstWord(lang)), not embedded data. That means:
//   - Adding/updating one dataset never requires touching the others.
//   - A language can exist with only bigrams loaded (today's actual
//     state for en/fr) and gain words/sentences later with zero code
//     changes - just drop the CSV in.
//   - No duplication (a word's popularity lives in exactly one place,
//     not copied into every bigram/sentence that happens to use it).
//
// This is the Go equivalent of the "Language OOP" idea: Language is the
// object, Word/Bigram/Sentence are its data, and lookup methods are the
// cross-referencing - just without literal object nesting, which would
// create sync problems across independently-growing datasets.
package langdata

import "strings"

// Word is one entry in a language's word list. Risk is optional (0 means
// "not scored" as much as "no risk" - Popularity==0 is the same kind of
// ambiguity inherent to optional numeric fields in a flat file; callers
// that care about the distinction should check WordCount()/HasWords()
// before trusting a zero value).
type Word struct {
	Text       string  `json:"text"`
	Popularity int     `json:"popularity,omitempty"`
	Risk       float64 `json:"risk,omitempty"`
}

// Bigram is one word-pair entry. First/Second are derived from Text at
// load time (split on the space), so a caller can look up either half's
// full Word data from the same Language without the bigram itself storing
// a copy of it.
type Bigram struct {
	Text       string `json:"text"`
	First      string `json:"first"`
	Second     string `json:"second"`
	Popularity int    `json:"popularity,omitempty"`
}

// FirstWord/SecondWord resolve this bigram's halves against a Language's
// word list - the "reference," done as a lookup rather than embedding.
func (b Bigram) FirstWord(lang *Language) (Word, bool)  { return lang.Word(b.First) }
func (b Bigram) SecondWord(lang *Language) (Word, bool) { return lang.Word(b.Second) }

// Sentence is one sentence-frequency entry.
type Sentence struct {
	Text       string `json:"text"`
	Popularity int    `json:"popularity,omitempty"`
}

// Words tokenizes this sentence and resolves each token against a
// Language's word list - again a lookup, not stored data, so a sentence
// added before the word list exists still works once the word list
// catches up (nothing needs re-processing).
func (s Sentence) Words(lang *Language) []Word {
	var out []Word
	for _, tok := range strings.Fields(strings.ToLower(s.Text)) {
		tok = strings.Trim(tok, ".,!?;:\"'")
		if w, ok := lang.Word(tok); ok {
			out = append(out, w)
		}
	}
	return out
}

// Bigrams returns every consecutive word-pair in this sentence that's a
// known bigram in the given Language.
func (s Sentence) Bigrams(lang *Language) []Bigram {
	toks := strings.Fields(strings.ToLower(s.Text))
	var out []Bigram
	for i := 0; i < len(toks)-1; i++ {
		if b, ok := lang.Bigram(toks[i] + " " + toks[i+1]); ok {
			out = append(out, b)
		}
	}
	return out
}

// Language bundles one language's three datasets plus fast lookup
// indices built once at load time.
type Language struct {
	Code string // "en"
	Name string // "English"

	Words     []Word
	Bigrams   []Bigram
	Sentences []Sentence

	wordIdx     map[string]int
	bigramIdx   map[string]int
	sentenceIdx map[string]int
}

func newLanguage(code, name string) *Language {
	return &Language{
		Code: code, Name: name,
		wordIdx: map[string]int{}, bigramIdx: map[string]int{}, sentenceIdx: map[string]int{},
	}
}

func (l *Language) addWord(w Word) {
	l.wordIdx[strings.ToLower(w.Text)] = len(l.Words)
	l.Words = append(l.Words, w)
}

func (l *Language) addBigram(b Bigram) {
	parts := strings.SplitN(b.Text, " ", 2)
	if len(parts) == 2 {
		b.First, b.Second = parts[0], parts[1]
	}
	l.bigramIdx[strings.ToLower(b.Text)] = len(l.Bigrams)
	l.Bigrams = append(l.Bigrams, b)
}

func (l *Language) addSentence(s Sentence) {
	l.sentenceIdx[strings.ToLower(s.Text)] = len(l.Sentences)
	l.Sentences = append(l.Sentences, s)
}

// Word looks up a word by text (case-insensitive), the "reference" every
// other type resolves through.
func (l *Language) Word(text string) (Word, bool) {
	i, ok := l.wordIdx[strings.ToLower(text)]
	if !ok {
		return Word{}, false
	}
	return l.Words[i], true
}

func (l *Language) Bigram(text string) (Bigram, bool) {
	i, ok := l.bigramIdx[strings.ToLower(text)]
	if !ok {
		return Bigram{}, false
	}
	return l.Bigrams[i], true
}

func (l *Language) Sentence(text string) (Sentence, bool) {
	i, ok := l.sentenceIdx[strings.ToLower(text)]
	if !ok {
		return Sentence{}, false
	}
	return l.Sentences[i], true
}

// Capability flags - a language is expected to gain datasets over time
// (bigrams today, words/sentences later), so callers should check these
// rather than assume all three are always present.
func (l *Language) HasWords() bool     { return len(l.Words) > 0 }
func (l *Language) HasBigrams() bool   { return len(l.Bigrams) > 0 }
func (l *Language) HasSentences() bool { return len(l.Sentences) > 0 }

// BigramPlausibility scores text by the fraction of its consecutive word
// pairs that are known bigrams - moved here (from the former
// internal/ngram package) now that bigram data lives in this unified
// model. See internal/ngram for the compatibility wrapper other packages
// still call.
func (l *Language) BigramPlausibility(text string) float64 {
	if !l.HasBigrams() {
		return 0
	}
	words := tokenize(text)
	if len(words) < 2 {
		return 0
	}
	hits := 0
	for i := 0; i < len(words)-1; i++ {
		if _, ok := l.Bigram(words[i] + " " + words[i+1]); ok {
			hits++
		}
	}
	return float64(hits) / float64(len(words)-1)
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
