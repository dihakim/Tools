// internal/cipher/static_sub.go
//
// Generic static symbol substitution engine for seven cipher families:
// braille, arrow, wingdings, simple_symbols, symbol_lookalikes,
// vowel_to_number, and emoticons. All seven share the same structure
// (a map from cipher symbols to plaintext characters, with optional
// variants), so they're driven by a single embedded JSON data file
// rather than duplicating encode/decode logic seven times.
//
// The JSON is generated from the Python reference implementation's
// MAP dicts (see internal/cipher/tools.go header comment for
// provenance). Each top-level key is the cipher method name; each
// variant holds the reverse map (cipher_symbol -> [plain_chars]).
package cipher

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
)

//go:embed static_sub.json
var staticSubJSON []byte

// staticMap holds one variant's reverse and forward maps.
type staticMap struct {
	reverse map[string][]string // cipher symbol -> plaintext chars (upper + lower)
	forward map[string]string   // plaintext (upper) -> first matching cipher symbol
}

// staticRegistry is the full registry: method name -> variant name -> staticMap.
var staticRegistry map[string]map[string]*staticMap

func init() {
	// Parse the JSON once at startup.
	var raw map[string]map[string]map[string][]string
	if err := json.Unmarshal(staticSubJSON, &raw); err != nil {
		panic("static_sub.json: " + err.Error())
	}
	staticRegistry = make(map[string]map[string]*staticMap, len(raw))
	for method, variants := range raw {
		staticRegistry[method] = make(map[string]*staticMap, len(variants))
		// Go maps iterate randomly; sort the variant names so the way a
		// method's variants are registered is deterministic.
		var variantNames []string
		for v := range variants {
			variantNames = append(variantNames, v)
		}
		sort.Strings(variantNames)
		for _, v := range variantNames {
			reverseRaw := variants[v]
			sm := &staticMap{
				reverse: make(map[string][]string, len(reverseRaw)),
				forward: make(map[string]string, len(reverseRaw)),
			}
			// Build reverse + forward in one pass. Forward maps a plaintext
			// character (upper-cased) to the FIRST cipher symbol (sorted
			// order) whose primary reading - plains[0] - is that character.
			// Building forward only from plains[0] keeps encode/decode
			// round-trips exact even when a symbol has multiple readings
			// (e.g. currency symbols that look like several letters): a
			// character only ever encodes to a symbol that decodes back to
			// it. Characters that are never a primary reading pass through.
			var symbolNames []string
			for k := range reverseRaw {
				symbolNames = append(symbolNames, k)
			}
			sort.Strings(symbolNames)
			for _, code := range symbolNames {
				plains := reverseRaw[code]
				sm.reverse[code] = plains
				if len(plains) > 0 {
					upper := strings.ToUpper(plains[0])
					if _, exists := sm.forward[upper]; !exists {
						sm.forward[upper] = code
					}
				}
			}
			staticRegistry[method][v] = sm
		}
	}
}

// staticVariants returns the available variant names for a method, in a
// deterministic order with "standard" / "classic" first (matching the
// default-variant convention used by the reference framework).
func staticVariants(method string) []string {
	variants, ok := staticRegistry[method]
	if !ok {
		return nil
	}
	group := func(name string) int {
		if name == "standard" || name == "classic" {
			return 0
		}
		return 1
	}
	var out []string
	for v := range variants {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		gi, gj := group(out[i]), group(out[j])
		if gi != gj {
			return gi < gj
		}
		return out[i] < out[j]
	})
	return out
}

// staticEncode encodes plaintext using the first matching cipher symbol
// per character. The key parameter selects the variant; if empty, the
// first variant (standard/classic) is used.
func staticEncode(method, variant, plaintext string) string {
	sm := staticMapFor(method, variant)
	if sm == nil {
		return plaintext
	}
	var b strings.Builder
	for _, r := range plaintext {
		ch := string(r)
		// Try uppercase match first (maps are case-insensitive on the
		// plaintext side for most ciphers).
		if sym, ok := sm.forward[strings.ToUpper(ch)]; ok {
			b.WriteString(sym)
		} else if sym, ok := sm.forward[ch]; ok {
			b.WriteString(sym)
		} else {
			// Unmapped character: pass through unchanged.
			b.WriteRune(r)
		}
	}
	return b.String()
}

// staticDecode decodes ciphertext by greedily matching the longest
// cipher symbol at each position. Symbols that aren't in the map pass
// through unchanged.
func staticDecode(method, variant, ciphertext string) string {
	sm := staticMapFor(method, variant)
	if sm == nil {
		return ciphertext
	}

	// Build a sorted list of reverse keys (longest first) for greedy
	// matching. This is computed once per call; for very short texts
	// the overhead is negligible, and for long texts the map size is
	// bounded by the alphabet (~50 entries including multi-char tokens).
	keys := reverseKeys(sm)
	var b strings.Builder
	pos := 0
	for pos < len(ciphertext) {
		matched := false
		for _, k := range keys {
			if strings.HasPrefix(ciphertext[pos:], k) {
				if plains := sm.reverse[k]; len(plains) > 0 {
					b.WriteString(plains[0])
				}
				pos += len(k)
				matched = true
				break
			}
		}
		if !matched {
			b.WriteByte(ciphertext[pos])
			pos++
		}
	}
	return b.String()
}

// staticMapFor resolves a method+variant to the staticMap, falling back
// to the default variant (standard/classic, sorted deterministically) if
// variant is empty or unknown.
func staticMapFor(method, variant string) *staticMap {
	variants, ok := staticRegistry[method]
	if !ok {
		return nil
	}
	if variant != "" {
		if sm, ok := variants[variant]; ok {
			return sm
		}
	}
	for _, v := range staticVariants(method) {
		return variants[v]
	}
	return nil
}

// reverseKeys returns the reverse map keys sorted longest-first, then
// lexicographically, for greedy prefix matching.
func reverseKeys(sm *staticMap) []string {
	keys := make([]string, 0, len(sm.reverse))
	for k := range sm.reverse {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j]) // longest first
		}
		return keys[i] < keys[j]
	})
	return keys
}
