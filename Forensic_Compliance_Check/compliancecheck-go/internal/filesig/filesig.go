// internal/filesig/filesig.go
//
// Compares a file's actual magic bytes against what its extension claims.
// This is the "PDF that's actually an .exe" detector - one of the highest
// signal-to-noise checks in the whole tool, since a mismatch here is
// almost never innocent (renamed malware, disguised archives, mislabeled
// exfil staging files).
package filesig

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

//go:embed signatures.json
var embedded embed.FS

type sig struct {
	Type       string   `json:"type"`
	Extensions []string `json:"extensions"`
	MagicHex   []string `json:"magic_hex"`
	Offset     int      `json:"offset"`
}

type DB struct {
	byExt map[string][]sig // extension -> candidate signatures (an ext can appear in multiple, e.g. zip family)
}

func Load() (*DB, error) {
	b, err := embedded.ReadFile("signatures.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Signatures []sig `json:"signatures"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	db := &DB{byExt: map[string][]sig{}}
	for _, s := range doc.Signatures {
		for _, ext := range s.Extensions {
			db.byExt[strings.ToLower(ext)] = append(db.byExt[strings.ToLower(ext)], s)
		}
	}
	return db, nil
}

type CheckResult struct {
	ClaimedExt   string   `json:"claimed_ext"`
	KnownExt     bool     `json:"known_ext"`     // do we have signature rules for this extension at all
	Matched      bool     `json:"matched"`       // did the header match ANY signature for the claimed ext
	ActualType   string   `json:"actual_type"`   // best-guess real type based on header bytes, if different
	HeaderHex    string   `json:"header_hex"`
}

const maxHeaderBytes = 32

// Check reads the file header and compares it to what `ext` (no dot, lowercased) claims.
func (db *DB) Check(path, ext string) (CheckResult, error) {
	ext = strings.ToLower(strings.TrimPrefix(ext, "."))
	res := CheckResult{ClaimedExt: ext}

	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()

	header := make([]byte, maxHeaderBytes)
	n, _ := f.Read(header)
	header = header[:n]
	res.HeaderHex = hex.EncodeToString(header)

	rules, known := db.byExt[ext]
	res.KnownExt = known
	if !known {
		return res, nil
	}

	for _, r := range rules {
		if headerMatches(header, r) {
			res.Matched = true
			return res, nil
		}
	}

	// Header didn't match what the extension claims - figure out what it actually looks like.
	for otherExt, rules := range db.byExt {
		if otherExt == ext {
			continue
		}
		for _, r := range rules {
			if headerMatches(header, r) {
				res.ActualType = r.Type
				return res, nil
			}
		}
	}
	return res, nil
}

func headerMatches(header []byte, r sig) bool {
	for _, mh := range r.MagicHex {
		want, err := hex.DecodeString(mh)
		if err != nil {
			continue
		}
		off := r.Offset
		if off+len(want) > len(header) {
			continue
		}
		if hex.EncodeToString(header[off:off+len(want)]) == mh {
			return true
		}
	}
	return false
}
