// internal/extract/docx.go
//
// DOCX (and XLSX/PPTX, structurally similar) is a zip archive of XML parts.
// Pure stdlib: archive/zip + encoding/xml, zero third-party dependencies -
// deliberately, since every dependency is supply-chain surface a security/
// forensics tool shouldn't need to trust.
package extract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// mainDocParts, in priority order, per Office Open XML part naming.
var mainDocParts = []string{
	"word/document.xml",   // docx
	"xl/sharedStrings.xml", // xlsx (cell text lives here, not in sheet XML directly)
	"ppt/slides/slide1.xml", // pptx - only first slide as a representative sample
}

// DOCX extracts visible text from a .docx/.xlsx/.pptx file. Returns
// (text, ok) - ok is false if the file isn't a readable zip or has none of
// the expected parts (i.e. it's not actually this format despite the
// extension - which is itself useful signal, left to the caller).
func OOXML(path string) (string, bool) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", false
	}
	defer r.Close()

	var out strings.Builder
	found := false
	for _, partName := range mainDocParts {
		f := findZipFile(r, partName)
		if f == nil {
			continue
		}
		text, err := extractXMLText(f)
		if err != nil {
			continue
		}
		out.WriteString(text)
		out.WriteString("\n")
		found = true
	}
	// Slide text beyond slide1 - grab a bounded number so we don't choke on huge decks.
	count := 0
	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "ppt/slides/slide") && strings.HasSuffix(f.Name, ".xml") && f.Name != "ppt/slides/slide1.xml" {
			if count >= 50 {
				break
			}
			text, err := extractXMLText(f)
			if err == nil {
				out.WriteString(text)
				out.WriteString("\n")
				found = true
			}
			count++
		}
	}

	return out.String(), found
}

func findZipFile(r *zip.ReadCloser, name string) *zip.File {
	for _, f := range r.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// extractXMLText walks the XML and collects character data from text-bearing
// elements (<w:t> in Word, <t> inside <si> in shared strings, <a:t> in
// PowerPoint). We match on local element name only, ignoring namespace
// prefixes, since different producers vary those.
func extractXMLText(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	var out strings.Builder
	inText := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch se := tok.(type) {
		case xml.StartElement:
			local := se.Name.Local
			if local == "t" { // <w:t>, <a:t>, and shared-string <t> all end in local name "t"
				inText = true
			} else if local == "p" || local == "tr" || local == "tc" || local == "si" || local == "br" {
				// Paragraph/row/cell boundaries: insert a separator so distinct data
				// points (e.g. adjacent table cells: an SSN next to a credit card
				// number) don't get concatenated into one unbroken digit run, which
				// would silently break the PII regexes' word-boundary matching.
				out.WriteString("\n")
			}
		case xml.EndElement:
			if se.Name.Local == "t" {
				inText = false
			}
		case xml.CharData:
			if inText {
				out.Write(se)
			}
		}
	}
	return out.String(), nil
}
