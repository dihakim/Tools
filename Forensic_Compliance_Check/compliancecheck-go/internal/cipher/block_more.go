// internal/cipher/block_more.go
//
// Educational (toy) block cipher ports from the Python reference: Simple
// DES, Working SPN, and Working TEA. All are character-based — they
// operate on uppercase letters (adding/subtracting the key value mod 26)
// and pad to the block size with 'A'. Decrypt strips trailing 'A' padding,
// exactly like the reference's _remove_padding.
package cipher

import (
	"strings"
)

// desRstrip removes trailing 'A' padding.
func desRstrip(s string) string { return strings.TrimRight(s, "A") }

// --- Simple DES ---

// DesEncode encrypts s with a shifted two-character block. Non-alpha
// characters are skipped by the reference (result unchanged); alpha
// characters get the key value added mod 26. Block size is 2.
func DesEncode(s, key string) string {
	text := strings.ToUpper(s)
	if key == "" {
		return text
	}
	keyU := strings.ToUpper(key)
	text = padA(text, 2)
	var b strings.Builder
	for i := 0; i < len(text); i += 2 {
		block := text[i : i+2]
		if len(block) < 2 {
			block = padA(block, 2)
		}
		for j := 0; j < len(block); j++ {
			ch := block[j]
			if ch < 'A' || ch > 'Z' {
				b.WriteByte(ch)
				continue
			}
			kv := keyU[j%len(keyU)] - 'A'
			b.WriteByte(byte((int(ch-'A')+int(kv))%26) + 'A')
		}
	}
	return b.String()
}

// DesDecode reverses DesEncode.
func DesDecode(s, key string) string {
	text := strings.ToUpper(s)
	if key == "" {
		return text
	}
	keyU := strings.ToUpper(key)
	if len(text)%2 != 0 {
		text = padA(text, 2)
	}
	var b strings.Builder
	for i := 0; i < len(text); i += 2 {
		block := text[i : i+2]
		if len(block) < 2 {
			block = padA(block, 2)
		}
		for j := 0; j < len(block); j++ {
			ch := block[j]
			if ch < 'A' || ch > 'Z' {
				b.WriteByte(ch)
				continue
			}
			kv := keyU[j%len(keyU)] - 'A'
			b.WriteByte(byte((int(ch-'A')-int(kv)+26)%26) + 'A')
		}
	}
	return desRstrip(b.String())
}

// padA left-pads nothing; it appends 'A's up to the next multiple of
// block (mirroring _pad_text, which doesn't add a full block when the
// text is already a multiple).
func padA(s string, block int) string {
	r := len(s) % block
	if r == 0 {
		return s
	}
	return s + strings.Repeat("A", block-r)
}

// --- Working SPN ---

// spnRoundKeys replicates _key_expansion: if the key is shorter than 4,
// it is padded with "KEY"; then round keys are the first two 4-char
// chunks of (padded_key + "KEYKEY").
func spnRoundKeys(key string) [2]string {
	k := strings.ToUpper(key)
	if len(k) < 4 {
		k = k + "KEY"[:4-len(k)]
	}
	padded := k + "KEYKEY"
	var rk [2]string
	rk[0] = padded[:4]
	rk[1] = padded[4:8]
	return rk
}

// spnAdd subtracts (or adds) the round key mod 26 over a 4-char state,
// skipping non-alpha.
func spnAdd(state, key string, subtract bool) string {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		t := state[i]
		kv := key[i%len(key)] - 'A'
		if t < 'A' || t > 'Z' {
			b.WriteByte(t)
			continue
		}
		val := int(t-'A') - int(kv)
		if !subtract {
			val = int(t-'A') + int(kv)
		}
		val %= 26
		if val < 0 {
			val += 26
		}
		b.WriteByte(byte(val) + 'A')
	}
	out := b.String()
	return padA(out, 4)
}

// spnSubstitute applies ROT13 (self-inverse).
func spnSubstitute(state string) string {
	var b strings.Builder
	for i := 0; i < len(state); i++ {
		ch := state[i]
		if ch >= 'A' && ch <= 'Z' {
			b.WriteByte('A' + (ch-'A'+13)%26)
		} else {
			b.WriteByte(ch)
		}
	}
	out := b.String()
	return padA(out, 4)
}

// SpnEncode encrypts with the two-round SPN.
func SpnEncode(s, key string) string {
	text := strings.ToUpper(s)
	text = padA(text, 4)
	rk := spnRoundKeys(key)
	var b strings.Builder
	for i := 0; i < len(text); i += 4 {
		block := text[i : i+4]
		state := padA(block, 4)
		state = spnAdd(state, rk[0], false)
		state = spnSubstitute(state)
		state = reverseString(state)
		state = spnAdd(state, rk[1], false)
		b.WriteString(state)
	}
	return b.String()
}

// SpnDecode reverses SpnEncode.
func SpnDecode(s, key string) string {
	text := strings.ToUpper(s)
	if len(text)%4 != 0 {
		text = padA(text, 4)
	}
	rk := spnRoundKeys(key)
	var b strings.Builder
	for i := 0; i < len(text); i += 4 {
		block := text[i : i+4]
		state := padA(block, 4)
		state = spnAdd(state, rk[1], true)
		state = reverseString(state)
		state = spnSubstitute(state)
		state = spnAdd(state, rk[0], true)
		b.WriteString(state)
	}
	return desRstrip(b.String())
}

func reverseString(s string) string {
	r := []byte(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// --- Working TEA ---

// TeaEncode uses 8-char blocks, preserving non-alphabetical characters
// and adding the key value mod 26 to alpha chars.
func TeaEncode(s, key string) string {
	text := strings.ToUpper(s)
	if key == "" {
		return text
	}
	keyU := strings.ToUpper(key)
	text = padA(text, 8)
	var b strings.Builder
	for i := 0; i < len(text); i += 8 {
		block := text[i : i+8]
		if len(block) < 8 {
			block = block + strings.Repeat("A", 8-len(block))
		}
		block = block[:8]
		for j := 0; j < len(block); j++ {
			ch := block[j]
			if ch < 'A' || ch > 'Z' {
				b.WriteByte(ch)
				continue
			}
			kv := keyU[j%len(keyU)] - 'A'
			b.WriteByte(byte((int(ch-'A')+int(kv))%26) + 'A')
		}
	}
	return b.String()
}

// TeaDecode reverses TeaEncode and strips padding.
func TeaDecode(s, key string) string {
	text := strings.ToUpper(s)
	if key == "" {
		return text
	}
	keyU := strings.ToUpper(key)
	if len(text)%8 != 0 {
		text = padA(text, 8)
	}
	var b strings.Builder
	for i := 0; i < len(text); i += 8 {
		block := text[i : i+8]
		if len(block) < 8 {
			block = block + strings.Repeat("A", 8-len(block))
		}
		block = block[:8]
		for j := 0; j < len(block); j++ {
			ch := block[j]
			if ch < 'A' || ch > 'Z' {
				b.WriteByte(ch)
				continue
			}
			kv := keyU[j%len(keyU)] - 'A'
			b.WriteByte(byte((int(ch-'A')-int(kv)+26)%26) + 'A')
		}
	}
	return desRstrip(b.String())
}