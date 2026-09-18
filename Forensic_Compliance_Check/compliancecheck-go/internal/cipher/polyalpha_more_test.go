package cipher

import (
	"testing"

	"compliancecheck/internal/langdetect"
)

func testDetector() *langdetect.Detector {
	det, err := langdetect.Load()
	if err != nil {
		panic(err)
	}
	return det
}

func TestBeaufortSymmetryAndRoundTrip(t *testing.T) {
	cases := []struct{ plain, key string }{
		{"ATTACK AT DAWN", "KEY"},
		{"the quick brown fox jumps", "BEAUFORT"},
		{"Hello, World!", "SECRET"},
	}
	for _, c := range cases {
		enc := BeaufortEncode(c.plain, c.key)
		// Beaufort is an involution: applying the same keyed operation again
		// (via Decode, which IS Encode) must return the plaintext.
		if dec := BeaufortDecode(enc, c.key); dec != c.plain {
			t.Errorf("Beaufort round trip %q key %q: enc=%q dec=%q", c.plain, c.key, enc, dec)
		}
		if again := BeaufortEncode(enc, c.key); again != c.plain {
			t.Errorf("Beaufort double-application %q key %q: got %q", c.plain, c.key, again)
		}
	}
}

func TestBeaufortVector(t *testing.T) {
	// Hand-computed with rotating keystream K,E,Y (10,4,24), C = K - P:
	// A(0)->K, T(19)->L, T(19)->F, A(0)->K, C(2)->C, K(10)->O => "KLFKCO".
	if got := BeaufortEncode("ATTACK", "KEY"); got != "KLFKCO" {
		t.Errorf("BeaufortEncode(ATTACK, KEY) = %q, want KLFKCO", got)
	}
}

func TestBeaufortCrack(t *testing.T) {
	// A sufficiently long Beaufort text under a short key must crack back to
	// the original phrase with the key recovered. Construct it from a
	// naturally-spaced English sentence (decoding validates on the spaced
	// text, matching how the crack gate works).
	plain := "the quick brown fox jumps over the lazy dog while the moon rises high above the silent hills and every star shines bright tonight my friends"
	key := "SECRET"
	enc := BeaufortEncode(plain, key)
	if len(onlyLetters(enc)) < 100 {
		t.Fatalf("test text too short for IC detection")
	}
	crack, ok := CrackBeaufortOnly(enc, testDetector())
	if !ok {
		t.Fatalf("Beaufort crack failed (enc from key %q)", key)
	}
	if crack.Key != key {
		t.Errorf("recovered key %q, want %q", crack.Key, key)
	}
	if crack.Plaintext != plain {
		t.Errorf("recovered text differs:\n got %q\nwant %q", crack.Plaintext, plain)
	}
}

func TestAutokeyVector(t *testing.T) {
	// Hand-computed: key KEY (K=10,E=4,Y=24), plaintext HELLO. Keystream is
	// KEY then HELLO: H+K->R, E+E->I, L+Y->J, L+H->S, O+E->S => "RIJSS".
	if got := AutokeyEncode("HELLO", "KEY"); got != "RIJSS" {
		t.Errorf("AutokeyEncode(HELLO, KEY) = %q, want RIJSS", got)
	}
	if got := AutokeyDecode("RIJSS", "KEY"); got != "HELLO" {
		t.Errorf("AutokeyDecode(RIJSS, KEY) = %q, want HELLO", got)
	}
}

func TestAutokeyRoundTrip(t *testing.T) {
	cases := []struct{ plain, key string }{
		{"commanders knife rises tonight", "QUEENLY"},
		{"Only letters shift, spaces pass through! 123", "KEY"},
		{"hello world", "K"},
		{"The quick brown fox", "THEPEN"},
	}
	for _, c := range cases {
		enc := AutokeyEncode(c.plain, c.key)
		if dec := AutokeyDecode(enc, c.key); dec != c.plain {
			t.Errorf("Autokey round trip %q key %q: enc=%q dec=%q", c.plain, c.key, enc, dec)
		}
	}
}

func TestAutokeyRequiresKeyInTools(t *testing.T) {
	res := Decode("autokey", "RIJSS", "", "", nil)
	if res.Success || res.Error == "" {
		t.Errorf("expected autokey decode without key to fail with a message, got success=%v err=%q", res.Success, res.Error)
	}
}