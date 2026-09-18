package pii

import "testing"

// TestDecodeTextScorePositive: decoded plaintext containing PII-shaped
// structure (email, name pair, phone) must yield a small nonzero boost.
func TestDecodeTextScorePositive(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		name string
		text string
	}{
		{"email", "reach me at john.brown@example.com please"},
		{"name pair", "I met David Smith at the conference"},
		{"phone", "you can call the office at (555) 123-4567 today"},
	}
	for _, c := range cases {
		if s := d.DecodeTextScore(c.text); s <= 0 {
			t.Errorf("%s: expected a positive boost, got %v", c.name, s)
		} else if s > 0.15 {
			t.Errorf("%s: boost %v must stay modest (cap 0.15)", c.name, s)
		}
	}
}

// TestDecodeTextScoreZero: text with no PII-shaped structure must get no
// boost - this is what keeps the signal honest for random shift garbage.
func TestDecodeTextScoreZero(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s := d.DecodeTextScore("qwzxrptm kviivij wkh txlfn eurzq"); s != 0 {
		t.Fatalf("expected zero boost for PII-free text, got %v", s)
	}
}

// TestDecodeTextScoreRanksAfterConfidenceElsewhere: a PII-dense text should
// score at least as high as a lone email - multiple signals accumulate but
// stay within the cap.
func TestDecodeTextScoreAccumulates(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	lone := d.DecodeTextScore("call john.brown@example.com")
	dense := d.DecodeTextScore("call john.brown@example.com or David Smith at (555) 123-4567, SSN 123-45-6789")
	if dense < lone {
		t.Fatalf("expected a PII-dense text to score >= a lone email: lone=%v dense=%v", lone, dense)
	}
}
