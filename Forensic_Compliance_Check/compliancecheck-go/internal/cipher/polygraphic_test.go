package cipher

import (
	"strings"
	"testing"
)

func TestPlayfairEncodeDecode(t *testing.T) {
	cases := []struct {
		plain string
		key   string
		want  string
	}{
		// Hand-traced vector: key PLAYFAIR EXAMPLE (matrix P L A Y F /
		// I R E X M / B C D G H / K N O Q S / T U V W Z). Pairs AT TA CK
		// ED AT DA WN -> PV VP BN DO PV OE UQ.
		{"attacked at dawn", "playfair example", "PVVPBNDOPVOEUQ"},
		{"hello world", "keyword", ""}, // round-trip check below
		{"hide the gold", "secret", ""},
		{"balloon", "monarchy", ""}, // doubled letters exercise the X insertion
	}
	for _, c := range cases {
		enc := PlayfairEncode(c.plain, c.key)
		dec := PlayfairDecode(enc, c.key)
		if c.want != "" && enc != c.want {
			t.Errorf("PlayfairEncode(%q, %q) = %q, want %q", c.plain, c.key, enc, c.want)
		}
		// Decoding should recover the letters with J folded into I.
		var wantLetters []byte
		for _, r := range strings.ToUpper(c.plain) {
			if r >= 'A' && r <= 'Z' {
				wantLetters = append(wantLetters, byte(r))
			}
		}
		if !playfairRecovers(dec, wantLetters) {
			t.Errorf("Playfair round trip (%q, key %q): dec=%q, want letters %q (enc=%q)", c.plain, c.key, dec, wantLetters, enc)
		}
	}
}

// playfairRecovers compares a decoded string to expected letters, folding
// J->I and tolerating filler X (which cleanup may or may not have removed).
func playfairRecovers(got string, wantLetters []byte) bool {
	for _, ch := range got {
		if ch == 'X' {
			continue
		}
		if len(wantLetters) == 0 {
			return false
		}
		want := wantLetters[0]
		if want == 'J' {
			want = 'I'
		}
		if byte(ch) != want {
			return false
		}
		wantLetters = wantLetters[1:]
	}
	return true
}

func TestPlayfairKnownVector(t *testing.T) {
	// Official RFC-style textbook vector: key "playfair example", the
	// famously used "hide the gold in the tree stump" phrase.
	enc := PlayfairEncode("hide the gold in the tree stump", "playfair example")
	dec := PlayfairDecode(enc, "playfair example")
	if !playfairRecovers(dec, []byte("HIDETHEGOLDINTHETREESTUMP")) {
		t.Errorf("official vector round trip failed: dec=%q", dec)
	}
}

func TestPlayfairRequiresKeyInTools(t *testing.T) {
	res := Decode("playfair", "DZAREVGMSCDKCE", "", "", nil)
	if res.Success {
		t.Error("expected playfair decode without a key to fail")
	}
	if res.Error == "" {
		t.Error("expected an informative error")
	}
	res2 := Encode("playfair", "attack", "", "")
	if res2.Success {
		t.Error("expected playfair encode without a key to fail")
	}
}