// internal/cipher/polyalpha_more.go
//
// Two more polyalphabetic ciphers that share Vigenère's Tabula Recta
// machinery but change how the key interacts with the plaintext:
//
//   Beaufort: C = (K - P) mod 26, key letter subtracted from the
//   plaintext rather than added - so encryption and decryption are the
//   same operation, and its per-column frequency attack is the mirror of
//   Vigenère's (see crack.go).
//
//   Autokey: a Vigenère variant whose keystream is the key followed by
//   the plaintext itself, so a short key never repeats. Decryption
//   re-derives the plaintext as it goes and feeds those recovered letters
//   back into the keystream. There is no reliable keyless shortcut in
//   this port (mirroring the reference implementation's weak auto-solve),
//   so a key is always required.
package cipher

import "strings"

// beaufort applies the symmetric Beaufort rule C = (K - P) mod 26 in both
// directions. Non-letters pass through; letter case is preserved.
func beaufort(s, key string) string {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return s
	}
	var keyIdx int
	var b strings.Builder
	for _, r := range s {
		var base rune
		switch {
		case r >= 'a' && r <= 'z':
			base = 'a'
		case r >= 'A' && r <= 'Z':
			base = 'A'
		default:
			b.WriteRune(r)
			continue
		}
		k := rune(key[keyIdx%len(key)]) - 'A'
		offset := ((k-(r-base))%26 + 26) % 26
		b.WriteRune(base + rune(offset))
		keyIdx++
	}
	return b.String()
}

// BeaufortEncode and BeaufortDecode are the same operation.
func BeaufortEncode(s, key string) string { return beaufort(s, key) }

// BeaufortDecode and BeaufortEncode are the same operation.
func BeaufortDecode(s, key string) string { return beaufort(s, key) }

// autokeyV2 transforms s with the Autokey keystream: the key first, then
// (after it runs out) the plaintext letters themselves. dir=+1 encrypts
// (C = P + K), dir=-1 decrypts (P = C - K); both recover/feed the
// plaintext into the keystream as letters are produced. Only alphabetic
// characters consume keystream; spaces and punctuation pass through.
func autokeyV2(s, key string, dir int) string {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return s
	}
	var seed []rune
	for _, r := range key {
		if r >= 'A' && r <= 'Z' {
			seed = append(seed, r-'A')
		}
	}
	if len(seed) == 0 {
		return s
	}
	keystream := append([]rune{}, seed...)
	var out []rune
	ksUsed := 0
	for _, r := range s {
		var base rune
		switch {
		case r >= 'a' && r <= 'z':
			base = 'a'
		case r >= 'A' && r <= 'Z':
			base = 'A'
		default:
			out = append(out, r)
			continue
		}
		// Appending every processed letter grows keystream so that its k-th
		// position (k >= seed length) always holds the plaintext letter that
		// feeds position k - the Autokey rule. So the shift for THIS letter
		// is already present at keystream[ksUsed].
		shift := keystream[ksUsed]
		var letter rune
		if dir == 1 {
			letter = base + (r-base+shift)%26
			out = append(out, letter)
			keystream = append(keystream, r-base)
		} else {
			letter = base + ((r-base-shift)%26+26)%26
			out = append(out, letter)
			keystream = append(keystream, letter-base)
		}
		ksUsed++
	}
	return string(out)
}

// AutokeyEncode encrypts s, seeding the keystream with key and then with
// the plaintext itself.
func AutokeyEncode(s, key string) string { return autokeyV2(s, key, 1) }

// AutokeyDecode decrypts s, seeding the keystream with key and then with
// the recovered plaintext.
func AutokeyDecode(s, key string) string { return autokeyV2(s, key, -1) }