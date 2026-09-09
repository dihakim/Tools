// internal/extract/pdf.go
//
// A minimal, dependency-free PDF text extractor. This is NOT a full PDF
// parser (no font/encoding tables, no CMaps for non-Latin fonts, no
// cross-reference stream parsing) - it's intentionally scoped to what's
// needed for PII/language scanning: find content streams, decompress them,
// and pull out the literal text drawn via Tj/TJ operators. Good enough for
// the large majority of PDFs produced by normal office/reporting tools;
// scanned/image-only PDFs and PDFs with custom font encodings won't yield
// text (they'd need OCR, out of scope here) - that's a limitation to be
// upfront about, not silently pretend doesn't exist.
package extract

import (
	"bytes"
	"compress/zlib"
	"io"
	"os"
	"regexp"
)

var streamRe = regexp.MustCompile(`(?s)<<(.*?)>>\s*stream\r?\n(.*?)endstream`)
var filterFlateRe = regexp.MustCompile(`/Filter\s*/FlateDecode`)

// textOpRe finds `(...) Tj`, `(...) '`, `(...) "` and `[...] TJ` operators -
// the PDF operators that actually draw text, along with their string operands.
var parenStringRe = regexp.MustCompile(`\(((?:[^()\\]|\\.)*)\)`)
var hexStringRe = regexp.MustCompile(`<([0-9A-Fa-f\s]+)>`)

// PDF extracts a best-effort plain-text rendering of a PDF's content streams.
// ok is false if the file couldn't be read or no text-bearing streams were found.
func PDF(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return "", false
	}

	var out bytes.Buffer
	found := false

	for _, m := range streamRe.FindAllSubmatch(data, -1) {
		dict, streamBody := m[1], m[2]
		content := streamBody
		if filterFlateRe.Match(dict) {
			decompressed, err := inflate(streamBody)
			if err != nil {
				continue // corrupt/partial stream - skip rather than fail the whole file
			}
			content = decompressed
		} else if bytes.Contains(dict, []byte("/Filter")) {
			// Some other filter (DCTDecode/JPXDecode for images, CCITTFax, etc.) -
			// not text content we can extract; skip rather than emit binary noise.
			continue
		}

		text := extractTextOperators(content)
		if text != "" {
			out.WriteString(text)
			out.WriteString("\n")
			found = true
		}
	}

	return out.String(), found
}

func inflate(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 32*1024*1024)) // cap decompressed size, avoid zip-bomb style abuse
}

// extractTextOperators scans a decompressed content stream for text-showing
// operators and pulls out the literal string operands, unescaping PDF's
// string escape sequences along the way.
func extractTextOperators(content []byte) string {
	var out bytes.Buffer

	// (string) Tj / ' / " - direct literal strings immediately followed by a text-show operator.
	for _, m := range parenStringRe.FindAllSubmatch(content, -1) {
		out.Write(unescapePDFString(m[1]))
		out.WriteByte(' ')
	}
	// <hex> Tj / TJ arrays containing hex strings.
	for _, m := range hexStringRe.FindAllSubmatch(content, -1) {
		if b := decodeHexPDFString(m[1]); len(b) > 0 {
			out.Write(b)
			out.WriteByte(' ')
		}
	}

	return out.String()
}

func unescapePDFString(b []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' && i+1 < len(b) {
			i++
			switch b[i] {
			case 'n':
				out.WriteByte('\n')
			case 'r':
				out.WriteByte('\r')
			case 't':
				out.WriteByte('\t')
			case '(', ')', '\\':
				out.WriteByte(b[i])
			default:
				out.WriteByte(b[i])
			}
			continue
		}
		out.WriteByte(b[i])
	}
	return out.Bytes()
}

func decodeHexPDFString(b []byte) []byte {
	var clean []byte
	for _, c := range b {
		if isHexDigit(c) {
			clean = append(clean, c)
		}
	}
	if len(clean)%2 != 0 {
		clean = clean[:len(clean)-1]
	}
	out := make([]byte, 0, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		hi := hexVal(clean[i])
		lo := hexVal(clean[i+1])
		out = append(out, byte(hi<<4|lo))
	}
	return out
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
