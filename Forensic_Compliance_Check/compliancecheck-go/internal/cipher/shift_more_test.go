package cipher

import "testing"

func TestKeyboardShiftVectors(t *testing.T) {
	cases := []struct {
		plain   string
		variant string
		shift   int
		want    string
	}{
		{"hello", "QWERTY", 2, "ktxxa"},       // reference example
		{"azerty", "AZERTY", 2, "ertyui"},     // reference example
		{"pass123", "QWERTY_FULL", 2, "]dff345"}, // reference example
		{"hello", "QWERTY", -1, "gwkki"},      // reference example (left shift)
	}
	for _, c := range cases {
		got := KeyboardEncode(c.plain, c.shift, c.variant)
		if got != c.want {
			t.Errorf("KeyboardEncode(%q, %d, %q) = %q, want %q", c.plain, c.shift, c.variant, got, c.want)
		}
		// Decode must invert it, whatever the variant.
		if dec := KeyboardDecode(got, c.shift, c.variant); dec != c.plain {
			t.Errorf("Keyboard round trip (%q, %d, %q) = %q", c.plain, c.shift, c.variant, dec)
		}
	}
}

func TestKeyboardRoundTrips(t *testing.T) {
	for _, v := range keyboardVariants() {
		if _, ok := keyboardOrderMaps[v]; !ok {
			t.Errorf("variant %q missing from keyboardOrderMaps", v)
		}
		for _, shift := range []int{1, 3, 26} {
			for _, p := range []string{"hello world", "tyhack 2026", "pass 123"} {
				enc := KeyboardEncode(p, shift, v)
				if dec := KeyboardDecode(enc, shift, v); dec != p {
					t.Errorf("round trip %q shift %d variant %q: enc=%q dec=%q", p, shift, v, enc, dec)
				}
			}
		}
	}
}

func TestKeyboardUnknownVariantFallsBack(t *testing.T) {
	got := KeyboardEncode("hello", 2, "COLEMAK")
	want := KeyboardEncode("hello", 2, "QWERTY")
	if got != want {
		t.Errorf("unknown variant should fall back to QWERTY: got %q want %q", got, want)
	}
}

func TestShiftThroughOrderCaseHandling(t *testing.T) {
	// Uppercase letters must still map through a lowercase order map; the
	// output is the map's own casing (uppercase maps give uppercase text,
	// lowercase maps lowercase) - matching the reference ShiftCipher.
	if got := ShiftThroughOrder("HELLO", "abcdefghijklmnopqrstuvwxyz", 3); got != "khoor" {
		t.Errorf("ShiftThroughOrder(HELLO, alphabet, 3) = %q, want khoor", got)
	}
	// Characters not in the map pass through.
	if got := ShiftThroughOrder("hi there!", "abcdefghijklmnopqrstuvwxyz", 1); got != "ij uifsf!" {
		t.Errorf("non-map chars should pass through: got %q, want %q", got, "ij uifsf!")
	}
}

func TestROT47(t *testing.T) {
	// Hand-computed from the standard mapping (printable ASCII rotated by 47
	// within 33..126): H->w, e->6, l->=, l->=, o->@, ','->'[', space kept,
	// W->(, o->@, r->C, l->=, d->5, '!'->P.
	if got := ROT47("Hello, World!"); got != "w6==@[ (@C=5P" {
		t.Errorf("ROT47(Hello, World!) = %q, want %q", got, "w6==@[ (@C=5P")
	}
	// Self-inverse.
	for _, s := range []string{"Hello, World!", "The quick brown fox", "abc123 !?", " "} {
		if again := ROT47(ROT47(s)); again != s {
			t.Errorf("ROT47 not self-inverse on %q: got %q", s, again)
		}
	}
}