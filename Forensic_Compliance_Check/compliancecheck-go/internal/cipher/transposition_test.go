package cipher

import (
	"strings"
	"testing"

	"compliancecheck/internal/langdetect"
)

var testPhrases = []string{
	"WE ARE DISCOVERED FLEE AT ONCE",
	"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THE SILENT EMPIRE WATCHES FROM THE NORTHERN TOWER",
	"ATTACK THE ENEMY FORTRESS AT DAWN AND RETREAT TO THE RIVER BEND BEFORE SUNSET",
}

func TestTranspositionRoundTrips(t *testing.T) {
	clean := "WEAREDISCOVEREDFLEEATONCE"
	for rails := 2; rails <= 12; rails++ {
		if dec := RailFenceDecode(RailFenceEncode(testPhrases[0], rails), rails); dec != clean {
			t.Fatalf("railfence rails=%d: got %q", rails, dec)
		}
	}
	for d := 2; d <= 12; d++ {
		if dec := ScytaleDecode(ScytaleEncode(testPhrases[0], d), d); dec != clean {
			t.Fatalf("scytale diameter=%d: got %q", d, dec)
		}
	}
	for _, key := range []string{"KEY", "SECRET", "ZEBRA", "ALPHA", "321", "2143"} {
		if dec := ColumnarDecode(ColumnarEncode(testPhrases[0], key), key); dec != clean {
			t.Fatalf("columnar key=%q: got %q", key, dec)
		}
	}
}

func TestTranspositionAutoSolve(t *testing.T) {
	det, err := langdetect.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range testPhrases {
		clean := cleanUppercaseLetters(phrase)
		for rails := 2; rails <= 9; rails++ {
			crack, ok := CrackRailFence(RailFenceEncode(phrase, rails), det)
			if !ok || crack.Plaintext != clean {
				t.Errorf("railfence %d: ok=%v key=%q plaintext=%q", rails, ok, crack.Key, crack.Plaintext)
			}
		}
		for d := 3; d <= 8; d++ {
			crack, ok := CrackScytale(ScytaleEncode(phrase, d), det)
			if !ok || crack.Plaintext != clean {
				t.Errorf("scytale %d: ok=%v key=%q plaintext=%q", d, ok, crack.Key, crack.Plaintext)
			}
		}
		for _, key := range []string{"KEY", "SECRET", "ZEBRA", "ALPHA", "4321", "3214"} {
			crack, ok := CrackColumnar(ColumnarEncode(phrase, key), det)
			if !ok || crack.Plaintext != clean {
				t.Errorf("columnar %q: ok=%v key=%q plaintext=%q", key, ok, crack.Key, crack.Plaintext)
			}
		}
	}
}

func TestTranspositionRejectsGibberish(t *testing.T) {
	det, err := langdetect.Load()
	if err != nil {
		t.Fatal(err)
	}
	scramble := "QKZRFBVDMXNPWLSJGHTCYUAIOEQUXKPLMNVZTASYFHWRCBJGRDVKLOMPQNXTUZW"
	if crack, ok := CrackRailFence(scramble, det); ok {
		t.Errorf("scramble cracked as railfence: %+v", crack)
	}
	if crack, ok := CrackColumnar(scramble, det); ok {
		t.Errorf("scramble cracked as columnar: %+v", crack)
	}
	// Non-transposition ciphertext (same letters, wrong order mechanism):
	// these must NOT be reported as solved transpositions.
	vig := VigenereEncode("THIS IS A LONG ENOUGH PIECE OF ENGLISH TEXT TO CONFUSE ANY DETECTOR", "KEY")
	if crack, ok := CrackColumnar(vig, det); ok {
		t.Errorf("vigenere cracked as columnar: %+v", crack)
	}
	caesar := CaesarEncode("THIS IS A LONG ENOUGH PIECE OF ENGLISH TEXT TO CONFUSE ANY DETECTOR", 7)
	if crack, ok := CrackScytale(caesar, det); ok {
		t.Errorf("caesar cracked as scytale: %+v", crack)
	}
	randScramble := "JQXVOPBNLWMSKTYCFUHIDGZRAKPTQWMBXCFYHGZO"
	if !strings.Contains(randScramble, "Q") {
		t.Fatal("unreachable")
	}
}