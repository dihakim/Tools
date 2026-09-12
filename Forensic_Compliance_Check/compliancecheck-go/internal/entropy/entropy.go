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

// Band classifies a whole-file entropy value into the ranges forensic
// literature commonly cites for distinguishing content types - plaintext,
// executable code, compressed data, and encrypted data occupy
// characteristically different (if overlapping) entropy bands. This is a
// coarse classification, not a certain one (the ranges overlap, especially
// executable-vs-compressed), but it's more informative than a flat
// high/low threshold for a human reviewing a report.
type Band string

const (
	BandLow         Band = "low"         // < 4.0 - repetitive/structured data, sparse text
	BandPlaintext   Band = "plaintext"   // 4.0-5.5 - typical human-readable text
	BandExecutable  Band = "executable"  // 5.5-7.0 - typical compiled code
	BandCompressed  Band = "compressed"  // 7.0-7.9 - typical compressed archives/media
	BandEncrypted   Band = "encrypted"   // 7.9-8.0 - typical encrypted/high-quality-random data
)

func Classify(bitsPerByte float64) Band {
	switch {
	case bitsPerByte < 4.0:
		return BandLow
	case bitsPerByte < 5.5:
		return BandPlaintext
	case bitsPerByte < 7.0:
		return BandExecutable
	case bitsPerByte < 7.9:
		return BandCompressed
	default:
		return BandEncrypted
	}
}

// WindowResult is one sliding-window entropy sample.
type WindowResult struct {
	Offset  int     `json:"offset"`
	Entropy float64 `json:"entropy"`
	Band    Band    `json:"band"`
}

// SlidingWindowScan computes entropy in successive windows across the whole
// file (not just once for the file as a whole) - this is what makes
// steganography-style detection possible: data with an encrypted/compressed
// blob appended to an otherwise normal file (e.g. a hidden archive tacked
// onto a JPEG after its end marker) shows a clean, low-variance entropy
// profile for the legitimate portion and then a sharp, sustained jump at
// the boundary. A single whole-file average would blur that signal away
// (a mostly-plaintext file with a small appended blob might not even push
// the OVERALL average past the high-entropy threshold).
func SlidingWindowScan(data []byte, windowSize int) []WindowResult {
	if windowSize <= 0 {
		windowSize = 4096
	}
	var out []WindowResult
	for offset := 0; offset < len(data); offset += windowSize {
		end := offset + windowSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		if len(chunk) < 64 {
			break // trailing partial window too small to be a meaningful sample
		}
		h := Shannon(chunk)
		out = append(out, WindowResult{Offset: offset, Entropy: h, Band: Classify(h)})
	}
	return out
}

// DetectEntropySpike looks for a steganography-style pattern: a sustained
// jump from a lower-entropy band into BandCompressed/BandEncrypted
// partway through the file, rather than the file being uniformly
// high-entropy throughout (which is just "this file is compressed/
// encrypted in its entirety" - not itself suspicious for e.g. a zip or
// media file). Returns the offset of the jump and the before/after
// entropy, or ok=false if no such jump pattern is present.
func DetectEntropySpike(windows []WindowResult) (offset int, before, after float64, ok bool) {
	if len(windows) < 4 {
		return 0, 0, 0, false // need enough windows for "before" to be an established baseline
	}
	// Baseline = median of the first half's entropy, so a few noisy windows
	// don't skew the comparison.
	firstHalf := windows[:len(windows)/2]
	baseline := medianEntropy(firstHalf)

	for i := len(windows) / 2; i < len(windows); i++ {
		w := windows[i]
		if w.Entropy-baseline >= 1.5 && (w.Band == BandCompressed || w.Band == BandEncrypted) && baseline < 7.0 {
			return w.Offset, baseline, w.Entropy, true
		}
	}
	return 0, 0, 0, false
}

func medianEntropy(windows []WindowResult) float64 {
	vals := make([]float64, len(windows))
	for i, w := range windows {
		vals[i] = w.Entropy
	}
	for i := 1; i < len(vals); i++ {
		for j := i; j > 0 && vals[j] < vals[j-1]; j-- {
			vals[j], vals[j-1] = vals[j-1], vals[j]
		}
	}
	return vals[len(vals)/2]
}
