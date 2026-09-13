// internal/scanner/storage.go
//
// Walks a target file or directory and produces one or more Findings per
// file: signature mismatch, PII matches, language/cipher signal, and - if
// nothing was flagged - a single CLEAN finding, so the report always
// covers every file scanned, not only the suspicious ones.
package scanner

import (
	"io/fs"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"compliancecheck/internal/cipher"
	"compliancecheck/internal/entropy"
	"compliancecheck/internal/extract"
	"compliancecheck/internal/filesig"
	"compliancecheck/internal/langdetect"
	"compliancecheck/internal/model"
	"compliancecheck/internal/pii"
)

// maxTextRead caps how much of a file we read into memory for text/PII/entropy
// analysis. Large binaries (video, disk images) are still signature-checked,
// just not content-scanned in full.
const maxTextRead = 5 * 1024 * 1024 // 5MB

type StorageScanner struct {
	FileSigDB   *filesig.DB
	PIIDetector *pii.Detector
	LangDet     *langdetect.Detector

	// PIIFilter, if non-empty, restricts PII findings to only these rule IDs
	// (e.g. {"EMAIL": true, "SSN_US": true}) - the "search for specific PII"
	// capability. Empty/nil means "all rules," the default. This lives here
	// (rather than as generic post-hoc filtering like the broader per-category
	// check selection) because it needs to affect what the PII detector
	// actually matches, not just what's displayed afterward.
	PIIFilter map[string]bool

	// CustomNames/CustomTerms are user-directed searches: "find this
	// specific person" (any combination of first/middle/last, matched
	// against realistic name-format variants) or "find this exact
	// string/regex" - see internal/pii/customsearch.go. Both are compiled
	// once via PrepareCustomSearches before a scan, not per-file.
	CustomNames []pii.NameQuery
	CustomTerms []pii.TermQuery

	compiledNameVariants map[int][]pii.NameVariant // index into CustomNames -> its variants
	compiledTerms        map[int]*regexp.Regexp    // index into CustomTerms -> its compiled pattern
}

// PrepareCustomSearches compiles CustomNames/CustomTerms once before
// scanning - called by the scanner's constructor path (webui/CLI), not
// per-file, since regex compilation is the expensive part. Returns any
// compile errors (e.g. invalid user-supplied regex) so the caller can
// report them clearly instead of silently dropping that search term.
func (s *StorageScanner) PrepareCustomSearches() []error {
	var errs []error
	s.compiledNameVariants = map[int][]pii.NameVariant{}
	for i, q := range s.CustomNames {
		variants, err := pii.GenerateNameVariants(q)
		if err != nil {
			errs = append(errs, fmt.Errorf("name search %d (%s %s %s): %w", i, q.First, q.Middle, q.Last, err))
			continue
		}
		s.compiledNameVariants[i] = variants
	}
	s.compiledTerms = map[int]*regexp.Regexp{}
	for i, q := range s.CustomTerms {
		re, err := q.Compile()
		if err != nil {
			errs = append(errs, fmt.Errorf("term search %d (%q): %w", i, q.Text, err))
			continue
		}
		s.compiledTerms[i] = re
	}
	return errs
}

func NewStorageScanner() (*StorageScanner, error) {
	sigDB, err := filesig.Load()
	if err != nil {
		return nil, err
	}
	piiDet, err := pii.Load()
	if err != nil {
		return nil, err
	}
	langDet, err := langdetect.Load()
	if err != nil {
		return nil, err
	}
	return &StorageScanner{FileSigDB: sigDB, PIIDetector: piiDet, LangDet: langDet}, nil
}

func (s *StorageScanner) Scan(target string) ([]model.Finding, error) {
	var findings []model.Finding

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			findings = append(findings, errFinding(path, err))
			return nil // keep scanning the rest of the tree
		}
		if d.IsDir() {
			return nil
		}
		findings = append(findings, s.scanFile(path)...)
		return nil
	}

	if info.IsDir() {
		if err := filepath.WalkDir(target, walkFn); err != nil {
			return nil, err
		}
	} else {
		findings = append(findings, s.scanFile(target)...)
	}

	return findings, nil
}

func (s *StorageScanner) scanFile(path string) []model.Finding {
	var out []model.Finding
	ext := strings.TrimPrefix(filepath.Ext(path), ".")

	// 1. File signature check.
	if ext != "" {
		if res, err := s.FileSigDB.Check(path, ext); err == nil && res.KnownExt && !res.Matched {
			f := model.NewFinding(model.CategoryStorage, "file_signature_mismatch", "File signature mismatch", model.SeverityHigh)
			f.Location = path
			f.Source = "storage.filesig"
			if res.ActualType != "" {
				f.Detail = "File extension claims ." + ext + " but header bytes match " + res.ActualType + " instead."
			} else {
				f.Detail = "File extension claims ." + ext + " but header bytes don't match any known signature for it."
			}
			f.Evidence["header_hex"] = res.HeaderHex
			f.Evidence["actual_type"] = res.ActualType
			out = append(out, f)
		}
	}

	// 2. Content-based checks: PII, language/cipher, entropy.
	// PDFs and Office XML formats need real text extraction - their raw bytes
	// are binary/compressed and would flood PII matching with garbage if
	// scanned directly (that was a real bug caught and fixed during testing).
	// Everything else falls back to the plain-text heuristic.
	var content []byte
	extractionAttempted := false
	extractionUnreliable := false
	switch strings.ToLower(ext) {
	case "pdf":
		extractionAttempted = true
		if text, ok := extract.PDF(path); ok {
			if looksLikeExtractedText(text) {
				content = []byte(text)
			} else {
				extractionUnreliable = true
			}
		}
	case "docx", "xlsx", "pptx":
		extractionAttempted = true
		if text, ok := extract.OOXML(path); ok {
			if looksLikeExtractedText(text) {
				content = []byte(text)
			} else {
				extractionUnreliable = true
			}
		}
	default:
		if data, readable := readTextIfSmallEnough(path); readable && looksLikeText(data) {
			content = data
		}
	}
	if extractionUnreliable {
		// Don't silently drop this and don't feed possibly-garbled text into PII
		// regex matching either (custom/subsetted font encodings, exotic PDF
		// producers, and password-protected/malformed files all land here) -
		// surface it honestly so a human knows this file needs manual review.
		f := model.NewFinding(model.CategoryStorage, "extraction_unreliable", "Text extraction produced unreliable output", model.SeverityInfo)
		f.Location = path
		f.Source = "storage.extract"
		f.Detail = "Extracted content didn't look like real text (likely a custom font encoding, scanned/image content, or corruption) - PII/language checks were skipped for this file's content. Recommend manual review."
		out = append(out, f)
	} else if extractionAttempted && content == nil {
		f := model.NewFinding(model.CategoryStorage, "extraction_no_text", "No extractable text found", model.SeverityInfo)
		f.Location = path
		f.Source = "storage.extract"
		f.Detail = "No text-bearing streams found - likely a scanned/image-only document, or an unsupported internal structure."
		out = append(out, f)
	}
	if len(content) > 0 {
		out = append(out, s.scanContent(path, content)...)
	}

	// Raw-bytes entropy scan - runs on EVERY file regardless of whether it
	// looked like text/was extractable, because the steganography case this
	// exists to catch (encrypted/compressed data appended to an otherwise
	// normal image or media file) is specifically a BINARY file scenario -
	// the text-content pipeline above never even sees these files.
	if raw, readable := readTextIfSmallEnough(path); readable {
		out = append(out, s.scanRawEntropy(path, raw)...)
	}

	if len(out) == 0 {
		f := model.NewFinding(model.CategoryStorage, "clean_file", "No issues detected", model.SeverityClean)
		f.Location = path
		f.Source = "storage.scanner"
		f.Detail = "File was scanned and passed all enabled checks."
		out = append(out, f)
	}

	return out
}

func (s *StorageScanner) scanContent(path string, data []byte) []model.Finding {
	var out []model.Finding
	text := string(data)

	// PII (in the raw content).
	out = append(out, s.piiFindings(path, text, "")...)

	// User-directed custom searches: specific named people and/or
	// arbitrary strings/regex - see internal/pii/customsearch.go.
	out = append(out, s.customSearchFindings(path, text)...)

	// Encoded substrings (base64/hex/base32/binary/URL-encoding) anywhere in
	// the text - these can appear inside otherwise perfectly normal files
	// (e.g. "here's the API token: <base64>..." in a README or config).
	for _, enc := range cipher.Detect(text, s.LangDet).Encodings {
		sev := model.SeverityInfo
		title := "Encoded content detected (" + enc.Type + ")"
		if enc.Decodable && enc.LooksMeaningful {
			sev = model.SeverityMedium
			title = "Decoded readable content from " + enc.Type + " encoding"
		}
		f := model.NewFinding(model.CategoryStorage, "encoded_content_"+enc.Type, title, sev)
		f.Location = path
		f.Source = "storage.cipher"
		f.Detail = "Sample: " + enc.Sample
		if enc.Decodable {
			f.Detail += " | Decoded: " + enc.Decoded
		}
		f.Evidence["encoding_type"] = enc.Type
		f.Evidence["decodable"] = enc.Decodable
		f.Evidence["looks_meaningful"] = enc.LooksMeaningful
		f.Evidence["position"] = enc.Position
		out = append(out, f)

		// If we decoded something that reads as real text, PII-scan the
		// decoded content too - a base64 blob is exactly how secrets get
		// pasted into config files and READMEs.
		if enc.Decodable && enc.LooksMeaningful {
			out = append(out, s.piiFindings(path, enc.Decoded, "decoded from "+enc.Type+" at position "+itoaSimple(enc.Position))...)
		}
	}

	// Language detection / classical cipher cracking.
	if len(strings.TrimSpace(text)) > 40 {
		lr := s.LangDet.Detect(text)
		if lr.Language == "" {
			if crack, ok := cipher.CrackClassical(text, s.LangDet); ok {
				f := model.NewFinding(model.CategoryStorage, "cipher_cracked_"+crack.Method, "Cipher decoded: "+crack.Method, model.SeverityHigh)
				f.Location = path
				f.Source = "storage.cipher"
				keyLabel := crack.Key
				if crack.Method == "caesar" {
					keyLabel = "shift " + crack.Key
				}
				f.Detail = "Text didn't match any known language, but decoded successfully as " + crack.Method +
					" (key: " + keyLabel + ") into recognizable " + crack.Language + " text."
				f.Evidence["method"] = crack.Method
				f.Evidence["key"] = crack.Key
				f.Evidence["language"] = crack.Language
				f.Evidence["confidence"] = crack.Confidence
				f.Evidence["decoded_preview"] = truncateSimple(crack.Plaintext, 500)
				out = append(out, f)

				// The whole point of decoding it: see if the plaintext itself
				// contains PII that would've stayed invisible while encrypted.
				out = append(out, s.piiFindings(path, crack.Plaintext, "decoded via "+crack.Method)...)
			} else {
				f := model.NewFinding(model.CategoryStorage, "unrecognized_language", "Text doesn't match any known language (possible cipher)", model.SeverityMedium)
				f.Location = path
				f.Source = "storage.langdetect"
				f.Detail = "No supported language scored above the confidence floor, and automatic cipher cracking (Caesar/ROT13/Atbash/Vigenère) didn't produce a confident decode either. Could be an unsupported language, a more complex cipher, or genuinely random data."
				f.Evidence["scores"] = lr.Scores
				out = append(out, f)
			}
		}
	}

	// Entropy - flag if the file is high-entropy overall, or contains a lot of internal variance.
	// (Whole-file entropy on the extracted/text content, in addition to the
	// raw-bytes scan in scanFile that also runs a sliding-window pass for
	// steganography-style detection across every file, not just text ones.)
	if entropy.LooksHighEntropy(data) {
		h := entropy.Shannon(data)
		f := model.NewFinding(model.CategoryStorage, "high_entropy_content", "High-entropy content (possible encrypted/encoded data)", model.SeverityLow)
		f.Location = path
		f.Source = "storage.entropy"
		f.Detail = "Content entropy is high enough to suggest encrypted, compressed, or encoded data rather than plain text (band: " + string(entropy.Classify(h)) + ")."
		f.Evidence["shannon_entropy_bits_per_byte"] = h
		f.Evidence["entropy_band"] = entropy.Classify(h)
		out = append(out, f)
	}

	return out
}

// piiFindings runs the PII detector against text and builds Findings.
// contextNote, if non-empty, is appended to each finding's detail so it's
// clear the match came from decoded/decrypted content rather than the
// file's literal bytes (e.g. "decoded via vigenere").
func (s *StorageScanner) scanRawEntropy(path string, data []byte) []model.Finding {
	// Only worth windowing a file large enough to have a meaningful "before"
	// and "after" - small files don't have room for a genuine steganography
	// pattern to show up as a sustained shift.
	if len(data) < 16*1024 {
		return nil
	}
	windows := entropy.SlidingWindowScan(data, 4096)
	offset, before, after, ok := entropy.DetectEntropySpike(windows)
	if !ok {
		// Deliberately not reporting "this file's raw bytes are high-entropy"
		// as its own finding here - for compressed formats (PDF/DOCX/ZIP/JPEG/
		// etc.) that's the normal, expected, non-suspicious state throughout
		// the whole file. The spike pattern (low entropy THEN a jump) is the
		// actual signal; uniform entropy either way isn't.
		return nil
	}

	f := model.NewFinding(model.CategoryStorage, "entropy_spike", "Entropy spike detected (possible appended/hidden data)", model.SeverityHigh)
	f.Location = path
	f.Source = "storage.entropy"
	f.Detail = "Entropy jumps from " + formatFloat(before) + " to " + formatFloat(after) +
		" bits/byte at offset " + itoaSimple(offset) + " and stays elevated - consistent with data " +
		"(encrypted, compressed, or otherwise non-native) appended after the file's legitimate content, " +
		"a common steganography pattern (e.g. a hidden archive tacked onto a JPEG after its end marker)."
	f.Evidence["spike_offset_bytes"] = offset
	f.Evidence["entropy_before"] = before
	f.Evidence["entropy_after"] = after
	f.Evidence["window_count"] = len(windows)
	return []model.Finding{f}
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}

// customSearchFindings runs any prepared user-directed name/term searches
// against text. Uses the pre-compiled variants/patterns from
// PrepareCustomSearches - if that was never called (no custom searches
// requested), these maps are nil and this is a no-op.
func (s *StorageScanner) customSearchFindings(path, text string) []model.Finding {
	var out []model.Finding

	for i, variants := range s.compiledNameVariants {
		q := s.CustomNames[i]
		nameLabel := strings.TrimSpace(strings.Join([]string{q.First, q.Middle, q.Last}, " "))
		for _, m := range pii.SearchNameVariants(text, variants) {
			sevMap := map[string]model.Severity{"high": model.SeverityHigh, "medium": model.SeverityMedium, "low": model.SeverityLow}
			f := model.NewFinding(model.CategoryStorage, "custom_name_search", "Custom name search match: "+nameLabel, sevMap[m.Confidence])
			f.Location = path
			f.Source = "storage.custom_search"
			f.Detail = "Matched \"" + m.MatchedText + "\" (format: " + m.VariantLabel + ", confidence: " + m.Confidence + ")"
			f.Evidence["query"] = nameLabel
			f.Evidence["variant"] = m.VariantLabel
			f.Evidence["confidence"] = m.Confidence
			f.Evidence["position"] = m.Position
			out = append(out, f)
		}
	}

	for i, re := range s.compiledTerms {
		q := s.CustomTerms[i]
		for _, m := range pii.SearchTerm(text, re) {
			f := model.NewFinding(model.CategoryStorage, "custom_term_search", "Custom search match", model.SeverityMedium)
			f.Location = path
			f.Source = "storage.custom_search"
			f.Detail = "Matched \"" + m.MatchedText + "\" for query \"" + q.Text + "\""
			f.Evidence["query"] = q.Text
			f.Evidence["is_regex"] = q.IsRegex
			f.Evidence["position"] = m.Position
			out = append(out, f)
		}
	}

	return out
}

func (s *StorageScanner) piiFindings(path, text, contextNote string) []model.Finding {
	var out []model.Finding
	for _, m := range s.PIIDetector.Scan(text) {
		if len(s.PIIFilter) > 0 && !s.PIIFilter[m.RuleID] {
			continue
		}
		f := model.NewFinding(model.CategoryStorage, "pii_"+strings.ToLower(m.RuleID), "PII detected: "+m.Label, model.Severity(m.Severity))
		f.Location = path
		f.Source = "storage.pii"
		f.Detail = m.Label + " found (redacted: " + m.Value + ")"
		if m.ContextMatched != "" {
			f.Detail += "; context keyword matched (" + m.ContextMatched + ")"
		}
		if contextNote != "" {
			f.Detail += " [" + contextNote + "]"
		}
		f.Evidence["rule_id"] = m.RuleID
		f.Evidence["base_severity"] = m.BaseSeverity
		if m.ChecksumPassed != nil {
			f.Evidence["checksum_passed"] = *m.ChecksumPassed
		}
		f.Evidence["position"] = m.Position
		if contextNote != "" {
			f.Evidence["source_context"] = contextNote
		}
		out = append(out, f)
	}

	if len(s.PIIFilter) == 0 || s.PIIFilter["PERSON_NAME"] {
		for _, m := range pii.DetectNames(text) {
			f := model.NewFinding(model.CategoryStorage, "pii_person_name", "PII detected: Person name", model.SeverityMedium)
			f.Location = path
			f.Source = "storage.pii"
			f.Detail = "Possible full name found: " + m.Forename + " " + string(m.Surname[0]) + strings.Repeat("*", len(m.Surname)-1)
			if contextNote != "" {
				f.Detail += " [" + contextNote + "]"
				f.Evidence["source_context"] = contextNote
			}
			f.Evidence["rule_id"] = "PERSON_NAME"
			f.Evidence["position"] = m.Position
			out = append(out, f)
		}
	}
	return out
}

func itoaSimple(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

func truncateSimple(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// looksLikeExtractedText is a quality gate on PDF/OOXML text extraction output.
// A custom/subsetted font encoding, a scanned image PDF, or a malformed file
// can all produce "text" that's really just noise (stray punctuation/symbol
// runs) - feeding that into PII regex matching would recreate the exact
// false-positive problem this rewrite exists to fix. Require a real
// preponderance of actual letters+digits (not just letters - PII-heavy
// documents like SSN/credit-card tables are legitimately number-dense)
// before trusting it.
func looksLikeExtractedText(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) < 20 {
		return false
	}
	alnum, total := 0, 0
	for _, r := range trimmed {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		total++
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			alnum++
		}
	}
	if total == 0 {
		return false
	}
	return float64(alnum)/float64(total) > 0.75
}

func readTextIfSmallEnough(path string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 || info.Size() > maxTextRead {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// looksLikeText samples the content and rejects anything that isn't
// overwhelmingly printable ASCII/whitespace - i.e. real prose, source code,
// config, CSV, etc. PDFs, Office binaries, images, and executables all fail
// this even though they may be "openable" as bytes, and that's the point:
// PII/language checks need actual text, not a binary/compressed format's
// raw bytes (which produce a flood of garbage regex matches otherwise).
func looksLikeText(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if len(sample) == 0 {
		return false
	}
	printable := 0
	for _, b := range sample {
		switch {
		case b == 0x00:
			return false // NUL byte is a strong binary signal, bail immediately
		case b == '\t' || b == '\n' || b == '\r':
			printable++
		case b >= 0x20 && b < 0x7f:
			printable++
		// Bytes >= 0x80 are only counted if they form valid UTF-8 - this lets
		// through accented/non-Latin text (French, Spanish, German, etc.)
		// without giving compressed/binary streams a free pass, since random
		// binary rarely decodes as valid UTF-8 continuation sequences.
		}
	}
	asciiRatio := float64(printable) / float64(len(sample))
	if asciiRatio > 0.85 {
		return true
	}
	// Borderline ASCII ratio: only accept if the sample is valid UTF-8 overall
	// (covers text that's genuinely heavy on accented/non-Latin characters).
	return asciiRatio > 0.60 && utf8.Valid(sample)
}

func errFinding(path string, err error) model.Finding {
	f := model.NewFinding(model.CategoryStorage, "scan_error", "Could not scan file", model.SeverityInfo)
	f.Location = path
	f.Source = "storage.scanner"
	f.Detail = err.Error()
	return f
}
