// internal/entropy/entropy.go
//
// Shannon entropy over byte content. High entropy text (close to the
// theoretical max ~8 bits/byte for arbitrary bytes, or noticeably above
// normal-language entropy for text ~4.0-4.5 bits/char) is a decent signal
// for encrypted/compressed/encoded blobs pasted into otherwise plain files
// (e.g. a base64 key dumped into a text file, an embedded encrypted blob).
package entropy

import "math"

// Shannon returns bits-of-entropy-per-byte for the given data, 0..8.
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// LooksHighEntropy is a practical threshold for "this chunk is probably not
// plain human-typed text or normal source code" - normal English/French/etc.
// prose in UTF-8 typically sits well below this.
func LooksHighEntropy(data []byte) bool {
	if len(data) < 24 {
		return false // too short to be a meaningful signal, avoid noisy false positives
	}
	return Shannon(data) >= 4.6
}
