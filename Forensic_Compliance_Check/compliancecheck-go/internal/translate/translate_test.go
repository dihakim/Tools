package translate

import (
	"strings"
	"testing"
)

// TestTranslateAutoChinese: input that stopword langdetect can't place
// (CJK text) but the Chinese dictionary fully covers should auto-select
// Chinese at 100% coverage.
func TestTranslateAutoChinese(t *testing.T) {
	res, ok := TranslateAuto("\u9010\u7389") // 逐玉
	if !ok {
		t.Fatal("expected an auto gloss for Chinese input")
	}
	if res.LanguageCode != "zh" {
		t.Fatalf("expected zh, got %q", res.LanguageCode)
	}
	if res.CoveragePct < 1.0 {
		t.Fatalf("expected full coverage, got %v", res.CoveragePct)
	}
	if !strings.Contains(strings.ToLower(res.RoughTranslation), "jade") {
		t.Fatalf("expected 'jade' in rough translation, got %q", res.RoughTranslation)
	}
}

// TestTranslateAutoGibberish: text that matches no dictionary in any
// available language must not clear the coverage bar.
func TestTranslateAutoGibberish(t *testing.T) {
	if _, ok := TranslateAuto("qwzxrptm"); ok {
		t.Fatal("expected no auto gloss for non-dictionary gibberish")
	}
}
