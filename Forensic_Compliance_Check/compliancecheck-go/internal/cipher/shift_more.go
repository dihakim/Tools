// internal/cipher/shift_more.go
//
// Additional shift-based ciphers: the keyboard shift (characters shifted
// along a keyboard-layout sequence rather than the alphabet) and ROT47
// (the whole printable-ASCII analog of ROT13). Both mirror the Python
// framework's ShiftCipher base: a fixed "order map" defines the alphabet
// to slide through, and the key is just how many steps to slide.
package cipher

import "strings"

// keyboardOrderMaps lists the four keyboard layouts the reference
// framework supports. Characters not present in the map (e.g. letters on
// non-QWERTY keyboards) pass through unchanged; everything in the map is
// case-insensitively matched, so a shifted character comes back in the
// case the layout uses (lowercase in all four maps).
var keyboardOrderMaps = map[string]string{
	"QWERTY": "1234567890qwertyuiopasdfghjklzxcvbnm",
	"AZERTY": "1234567890azertyuiopqsdfghjklmwxcvbn",
	// The reference source's DVORAK row ("...crldaoeui...") duplicates 'd';
	// a duplicated character would break round-tripping, so the extra 'd'
	// is dropped and the canonical Dvorak top/home/bottom rows are used.
	"DVORAK":      "1234567890pyfgcrlaoeuidhtns-;qjkxbmwvz",
	"QWERTY_FULL": "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./",
}

// keyboardVariants returns the supported layout names (stable order).
func keyboardVariants() []string {
	return []string{"QWERTY", "AZERTY", "DVORAK", "QWERTY_FULL"}
}

// ShiftThroughOrder slides every character that appears in order along it
// by shift steps (positive = toward the end), wrapping around at the ends.
// Characters outside the map pass through untouched. Lookup is
// case-insensitive; the replacement character is emitted as stored in the
// map (uppercase maps yield uppercase output, lowercase maps lowercase),
// matching the reference ShiftCipher._transform behavior.
func ShiftThroughOrder(s, order string, shift int) string {
	if order == "" {
		return s
	}
	seq := []rune(order)
	pos := make(map[rune]int, len(seq))
	for i, r := range seq {
		pos[r] = i
	}
	var b strings.Builder
	for _, r := range s {
		idx, ok := pos[r]
		if !ok {
			if up := upperRune(r); up != r {
				idx, ok = pos[up]
			}
		}
		if !ok {
			if lo := lowerRune(r); lo != r {
				idx, ok = pos[lo]
			}
		}
		if !ok {
			b.WriteRune(r)
			continue
		}
		n := ((idx+shift)%len(seq) + len(seq)) % len(seq)
		b.WriteRune(seq[n])
	}
	return b.String()
}

func upperRune(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func lowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

// keyboardLayout returns the order map for a variant, defaulting to QWERTY
// for unknown names so a bad variant never silently no-ops.
func keyboardLayout(variant string) string {
	if seq, ok := keyboardOrderMaps[variant]; ok {
		return seq
	}
	return keyboardOrderMaps["QWERTY"]
}

// keyboardLayoutName returns the canonical layout name for a variant,
// defaulting to QWERTY so unknown names resolve deterministically.
func keyboardLayoutName(variant string) string {
	if _, ok := keyboardOrderMaps[variant]; ok {
		return variant
	}
	return "QWERTY"
}

// KeyboardEncode shifts text along the given keyboard layout by shift
// steps (positive = toward the right on the physical row). Unknown
// variants fall back to QWERTY.
func KeyboardEncode(s string, shift int, variant string) string {
	return ShiftThroughOrder(s, keyboardLayout(variant), shift)
}

// KeyboardDecode is the inverse: the same slide in the other direction.
func KeyboardDecode(s string, shift int, variant string) string {
	return ShiftThroughOrder(s, keyboardLayout(variant), -shift)
}

// ROT47 rotates every printable-ASCII character (0x21 '!' .. 0x7E '~')
// by 47 steps within that 94-character range - the printable analog of
// ROT13, and like ROT13 it is its own inverse.
func ROT47(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 33 && r <= 126 {
			b.WriteRune(33 + (r-33+47)%94)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}