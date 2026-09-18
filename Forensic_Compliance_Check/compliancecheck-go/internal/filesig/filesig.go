// internal/filesig/filesig.go
//
// Compares a file's actual magic bytes against what its extension claims.
// This is the "PDF that's actually an .exe" detector - one of the highest
// signal-to-noise checks in the whole tool, since a mismatch here is
// almost never innocent (renamed malware, disguised archives, mislabeled
// exfil staging files).
//
// Signature data (internal/filesig/signatures.json) was derived from a
// structured file-signature export (84 entries, verified against real
// format specs during import - e.g. TAR's "ustar" at byte 257, ISO 9660's
// "CD001" at byte 32769, RIFF-container fourCC at byte 8, all confirmed
// correct against the actual published format specifications). Each
// signature can require MULTIPLE checkpoints (offset+bytes) that must ALL
// match - this is what makes it possible to tell WAV/AVI/WEBP apart even
// though they all share the same 4-byte "RIFF" prefix: the real
// disambiguator is a second fourCC field 8 bytes in, not something a
// single fixed-offset check could express.
//
// Reliable vs. heuristic: only genuine, format-guaranteed binary magic
// numbers (PE headers, ZIP/OOXML, images, audio/video containers,
// archives, SQLite, etc.) count toward "this extension is known and its
// header didn't match anything, therefore mismatch." Text-based formats
// whose first bytes aren't actually guaranteed by their format (a shebang
// line, a comment character, a JSON object's opening brace, an XML
// declaration) are marked non-reliable: they can still positively confirm
// a match, but their ABSENCE never triggers a mismatch verdict, since
// plenty of legitimate files of those types don't start that way (a
// sourced shell script often has no shebang; JSON/XML can have leading
// whitespace or a BOM; not every .html file declares DOCTYPE). Treating
// those as authoritative would have turned a lot of ordinary text files
// into false "signature mismatch" flags - the opposite of what this
// check exists to do.
package filesig

import (
	"embed"
	"encoding/hex"
	"os"
	"strings"

	"encoding/json"
)

//go:embed signatures.json
var embedded embed.FS

type checkpoint struct {
	Offset         int      `json:"offset"`
	Hex            string   `json:"hex,omitempty"`
	HexAlternatives []string `json:"hex_alternatives,omitempty"`
}

type sig struct {
	ID          int          `json:"id"`
	Extension   string       `json:"extension"`
	Description string       `json:"description"`
	Reliable    bool         `json:"reliable"`
	Checkpoints []checkpoint `json:"checkpoints"`
}

type DB struct {
	byExt map[string][]sig
}

func Load() (*DB, error) {
	b, err := embedded.ReadFile("signatures.json")
	if err != nil {
		return nil, err
	}
	var sigs []sig
	if err := json.Unmarshal(b, &sigs); err != nil {
		return nil, err
	}
	db := &DB{byExt: map[string][]sig{}}
	for _, s := range sigs {
		ext := strings.ToLower(s.Extension)
		db.byExt[ext] = append(db.byExt[ext], s)
	}
	return db, nil
}

type CheckResult struct {
	ClaimedExt        string `json:"claimed_ext"`
	KnownExt          bool   `json:"known_ext"`           // do we have at least one RELIABLE signature rule for this extension
	Matched           bool   `json:"matched"`             // did the header match a reliable signature for the claimed ext
	HeuristicMatched  bool   `json:"heuristic_matched"`   // matched a non-reliable (heuristic) rule - corroborating only
	ActualType        string `json:"actual_type"`         // best-guess real type based on header bytes, if different
	ActualDescription string `json:"actual_description,omitempty"`
	HeaderHex         string `json:"header_hex"`
}

const headerSampleBytes = 32 // just for the evidence field, not matching

// Check reads whatever bytes are needed (per-checkpoint, so a signature
// requiring bytes at offset 32769 doesn't force reading 32KB+ for every
// file) and compares them to what `ext` claims.
func (db *DB) Check(path, ext string) (CheckResult, error) {
	ext = strings.ToLower(strings.TrimPrefix(ext, "."))
	res := CheckResult{ClaimedExt: ext}

	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()

	sample := make([]byte, headerSampleBytes)
	n, _ := f.ReadAt(sample, 0)
	res.HeaderHex = hex.EncodeToString(sample[:n])

	rules := db.byExt[ext]
	reliableRules := onlyReliable(rules)
	res.KnownExt = len(reliableRules) > 0

	for _, r := range rules {
		if allCheckpointsMatch(f, r.Checkpoints) {
			if r.Reliable {
				res.Matched = true
				return res, nil
			}
			res.HeuristicMatched = true // keep looking for a reliable match too, but remember this
		}
	}
	if !res.KnownExt {
		return res, nil // nothing reliable to have mismatched against
	}

	// Header didn't match a reliable rule for the claimed extension - see
	// what it actually looks like, checking reliable signatures from every
	// OTHER extension.
	for otherExt, otherRules := range db.byExt {
		if otherExt == ext {
			continue
		}
		for _, r := range otherRules {
			if !r.Reliable {
				continue
			}
			if allCheckpointsMatch(f, r.Checkpoints) {
				res.ActualType = otherExt
				res.ActualDescription = r.Description
				return res, nil
			}
		}
	}
	return res, nil
}

func onlyReliable(sigs []sig) []sig {
	var out []sig
	for _, s := range sigs {
		if s.Reliable {
			out = append(out, s)
		}
	}
	return out
}

func allCheckpointsMatch(f *os.File, checkpoints []checkpoint) bool {
	if len(checkpoints) == 0 {
		return false
	}
	for _, cp := range checkpoints {
		if !checkpointMatches(f, cp) {
			return false
		}
	}
	return true
}

func checkpointMatches(f *os.File, cp checkpoint) bool {
	if len(cp.HexAlternatives) > 0 {
		buf := make([]byte, 1)
		if n, err := f.ReadAt(buf, int64(cp.Offset)); err != nil || n < 1 {
			return false
		}
		got := hex.EncodeToString(buf)
		for _, alt := range cp.HexAlternatives {
			if strings.EqualFold(got, alt) {
				return true
			}
		}
		return false
	}

	want, err := hex.DecodeString(cp.Hex)
	if err != nil || len(want) == 0 {
		return false
	}
	buf := make([]byte, len(want))
	n, err := f.ReadAt(buf, int64(cp.Offset))
	if err != nil || n < len(want) {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(buf), cp.Hex)
}
