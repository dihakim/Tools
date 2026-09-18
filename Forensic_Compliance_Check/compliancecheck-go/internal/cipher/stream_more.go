// internal/cipher/stream_more.go
//
// FIFTY-STREAM cipher family ports from the Python reference: RC4, LFSR,
// One-Time Pad, and a simplified Enigma rotor machine. All byte-oriented
// ciphers here use hex-encoded I/O (matching xor.go's convention - a raw
// byte stream isn't valid UTF-8, so the UI needs a displayable form).
// Enigma is character-based and uses plain text in/out.
//
// Keys are handled the same way as the Python reference framework:
// RC4 pads/strips to 16 bytes via SHA-256, LFSR to 4 bytes, and OTP uses
// the raw key. The reference generates a random IV for ChaCha20/Salsa20
// and prepends it to the ciphertext; an interactive CLI tool needs
// deterministic round-trips, so here the nonce is derived from the key
// (sha256(key)[:8]) instead.
package cipher

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// --- RC4 ---

// RC4Encode / RC4Decode are identical operations: RC4 is symmetric.
// The key is normalized to 16 bytes (SHA-256 of the raw key, truncated),
// matching the reference's KEY_SIZE=16 handling.
func RC4Encode(s, key string) string {
	data := rc4XOR([]byte(s), key)
	return hex.EncodeToString(data)
}

func rc4Key16(key []byte) []byte {
	if len(key) > 16 {
		return key[:16]
	}
	if len(key) < 16 {
		h := sha256.Sum256(key)
		return h[:16]
	}
	return key
}

// RC4Decode is RC4Encode (self-inverse).
func RC4Decode(hexStr, key string) (string, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	return string(rc4XOR(data, key)), nil
}

// rc4XOR runs RC4's KSA/PRGA over data with the given key.
func rc4XOR(data []byte, key string) []byte {
	if key == "" {
		return data
	}
	k := rc4Key16([]byte(key))
	var sbox [256]byte
	for i := range sbox {
		sbox[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(sbox[i]) + int(k[i%len(k)])) % 256
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}
	out := make([]byte, len(data))
	i, j := 0, 0
	for n := range data {
		i = (i + 1) % 256
		j = (j + int(sbox[i])) % 256
		sbox[i], sbox[j] = sbox[j], sbox[i]
		out[n] = data[n] ^ sbox[(int(sbox[i])+int(sbox[j]))%256]
	}
	return out
}

// --- LFSR ---

// lfsrPolynomials mirrors the reference's FEEDBACK_POLYNOMIALS table.
var lfsrPolynomials = map[string]uint32{
	"standard": 0x80000057,
	"alternate": 0x80200003,
	"simple":   0x8000001B,
}

// lfsrVariant gets the feedback mask for a variant name, defaulting to
// the standard polynomial.
func lfsrVariantMask(variant string) uint32 {
	if m, ok := lfsrPolynomials[variant]; ok {
		return m
	}
	return lfsrPolynomials["standard"]
}

// lfsrVariantName returns the canonical variant name, defaulting to
// "standard" so unknown names resolve deterministically.
func lfsrVariantName(variant string) string {
	if _, ok := lfsrPolynomials[variant]; ok {
		return variant
	}
	return "standard"
}

// lfsrStream produces the LFSR keystream XORed with data.
func lfsrStream(data []byte, variant string, key []byte) []byte {
	register := uint32(0)
	if len(key) >= 4 {
		register = uint32(key[0])<<24 | uint32(key[1])<<16 | uint32(key[2])<<8 | uint32(key[3])
	} else {
		padded := make([]byte, 4)
		copy(padded, key)
		register = uint32(padded[0])<<24 | uint32(padded[1])<<16 | uint32(padded[2])<<8 | uint32(padded[3])
	}
	if register == 0 {
		register = 0xACE1
	}
	mask := lfsrVariantMask(variant)
	out := make([]byte, len(data))
	for n := range data {
		var result byte
		for b := 0; b < 8; b++ {
			bit := register & 1
			result = result>>1 | byte(bit<<7)
			feedback := 0
			for m := mask; m != 0; m &= m - 1 {
				lsb := m & -m
				if register&lsb != 0 {
					feedback ^= 1
				}
			}
			register = register>>1 | uint32(feedback)<<31
		}
		out[n] = data[n] ^ result
	}
	return out
}

func lfsrKey4(key []byte) []byte {
	if len(key) > 4 {
		return key[:4]
	}
	if len(key) < 4 {
		h := sha256.Sum256(key)
		return h[:4]
	}
	return key
}

// LFSREncode encrypts s with a 32-bit LFSR keystream. The variant selects
// the feedback polynomial; the key is normalized to 4 bytes.
func LFSREncode(s, key, variant string) string {
	return hex.EncodeToString(lfsrStream([]byte(s), variant, keyBytes(key)))
}

// LFSRDecode decrypts hex ciphertext using the same LFSR parameters.
func LFSRDecode(hexStr, key, variant string) (string, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	return string(lfsrStream(data, variant, keyBytes(key))), nil
}

func keyBytes(key string) []byte {
	return []byte(key)
}

// --- One-Time Pad ---

var errOTPKeyTooShort = errors.New("otp key must be at least as long as the message")

// OTPEncode XORs the message with the raw key. The key must be at least
// as long as the message (perfect secrecy, key never reused).
func OTPEncode(s, key string) (string, error) {
	return otp(s, key, true)
}

// OTPDecode reverses OTPEncode.
func OTPDecode(hexStr, key string) (string, error) {
	return otp(hexStr, key, false)
}

func otp(data, key string, encode bool) (string, error) {
	k := []byte(key)
	if encode {
		in := []byte(data)
		if len(k) < len(in) {
			return "", errOTPKeyTooShort
		}
		for i := range in {
			in[i] ^= k[i%len(k)]
		}
		return hex.EncodeToString(in), nil
	}
	raw, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	if len(k) < len(raw) {
		return "", errOTPKeyTooShort
	}
	out := make([]byte, len(raw))
	for i := range raw {
		out[i] = raw[i] ^ k[i%len(k)]
	}
	return string(out), nil
}

// --- Enigma (simplified, from the Python reference) ---

// enigmaRotors holds the historical rotor wirings.
var enigmaRotors = []string{
	"EKMFLGDQVZNTOWYHXUSPAIBRCJ", "AJDKSIRUXBLHWTMCQGZNPYFVOE",
	"BDFHJLCPRTXVZNYEIWGAKMUSQO", "ESOVPZJAYQUIRHXLNFTGKDCMWB",
	"VZBRGITYUPSDNHLXAWMJQOFECK", "JPGVOUMFYQBENHTSZRKADLXCW",
	"NZJHGRCXMYSWBOUFAIVLPEKQDT", "FKQHTLXOCBJSPDZRAMEWNIUYGV",
}

// enigmaReflectors holds the reflector wirings (index 1 = Reflector B,
// the default, matching the reference).
var enigmaReflectors = []string{
	"EJMZALYXVBWFCRQUONTSPIKHGD", "YRUHQSLDPXNGOKMIEBFZCWVJAT",
	"FVPJIAOYEDRZXWGCTKUQSBNMHL",
}

// EnigmaEncode / EnigmaDecode are the same operation (the machine is
// symmetric). The key is rotor starting positions, e.g. "ABC"; the
// reference default is rotors I,II,III with reflector B and no ring
// offsets or plugboard.
func EnigmaEncode(s, key string) string {
	rotors := []int{0, 1, 2}
	positions := make([]int, 3)
	fullKey := strings.ToUpper(key)
	for i := 0; i < 3; i++ {
		if i < len(fullKey) {
			ch := fullKey[i]
			if ch >= 'A' && ch <= 'Z' {
				positions[i] = int(ch - 'A')
			}
		}
	}
	return enigmaCipherText(s, rotors, positions, 1)
}

// enigmaCipherText runs the Enigma machine over the text. Encode and
// decode are identical; rotors/positions default to the reference setup.
func enigmaCipherText(s string, rotors, positions []int, reflector int) string {
	current := append([]int(nil), positions...)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var b strings.Builder
	for _, r := range s {
		ch := byte(r)
		if ch >= 'a' && ch <= 'z' {
			ch -= 'a' - 'A'
		}
		if ch < 'A' || ch > 'Z' {
			b.WriteByte(ch)
			continue
		}
		// Advance rotors (first always; carry on wraparound).
		current[0] = (current[0] + 1) % 26
		for i := 0; i < len(current)-1; i++ {
			if current[i] == 0 {
				current[i+1] = (current[i+1] + 1) % 26
			}
		}
		idx := int(ch - 'A')
		// Forward pass (right to left).
		for i, rotorIdx := range rotors {
			rotor := enigmaRotors[rotorIdx]
			contact := (idx + current[i]) % 26
			outVal := int(rotor[contact] - 'A')
			idx = ((outVal-current[i])%26 + 26) % 26
		}
		// Reflector.
		idx = int(enigmaReflectors[reflector][idx] - 'A')
		// Reverse pass (left to right).
		for i := len(rotors) - 1; i >= 0; i-- {
			rotor := enigmaRotors[rotors[i]]
			contact := (idx + current[i]) % 26
			// Find input index that maps to contact in the rotor wiring.
			found := 0
			for j := 0; j < 26; j++ {
				if int(rotor[j]-'A') == contact {
					found = j
					break
				}
			}
			idx = ((found-current[i])%26 + 26) % 26
		}
		b.WriteByte(alphabet[idx])
	}
	return b.String()
}

// EnigmaDecode is EnigmaEncode (symmetric machine).
func EnigmaDecode(s, key string) string { return EnigmaEncode(s, key) }

// --- ChaCha20 and Salsa20 ---

// chachaSalsaPrepareKey always produces a full 32-byte SHA-256 key,
// matching the reference's overridden _prepare_key.
func chachaSalsaPrepareKey(key string) []byte {
	if key == "" {
		key = "chacha"
	}
	h := sha256.Sum256([]byte(key))
	return h[:]
}

// chachaSalsaNonce derives a deterministic 8-byte nonce from the key,
// replacing the reference's random IV (which would break manual round-trips).
func chachaSalsaNonce(key []byte) []byte {
	h := sha256.Sum256(key)
	return h[:8]
}

const (
	chachaSalsaConst0 = 0x61707865
	chachaSalsaConst1 = 0x3320646e
	chachaSalsaConst2 = 0x79622d32
	chachaSalsaConst3 = 0x6b206574
)

func chachaQuarterRound(state []uint32, a, b, c, d int) {
	state[a] = state[a] + state[b]
	state[d] ^= state[a]
	state[d] = rotl32(state[d], 16)
	state[c] = state[c] + state[d]
	state[b] ^= state[c]
	state[b] = rotl32(state[b], 12)
	state[a] = state[a] + state[b]
	state[d] ^= state[a]
	state[d] = rotl32(state[d], 8)
	state[c] = state[c] + state[d]
	state[b] ^= state[c]
	state[b] = rotl32(state[b], 7)
}

func salsaQuarterRound(y []uint32, a, b, c, d int) {
	y[b] ^= rotl32(y[a]+y[d], 7)
	y[c] ^= rotl32(y[b]+y[a], 9)
	y[d] ^= rotl32(y[c]+y[b], 13)
	y[a] ^= rotl32(y[d]+y[c], 18)
}

func rotl32(x uint32, n uint) uint32 {
	return x<<n | x>>(32-n)
}

// chachaKeystream generates the keystream blocks for ChaCha20.
func chachaKeystream(key, nonce []byte, rounds int, dataLen int) []byte {
	const blockSize = 64
	out := make([]byte, 0, dataLen)
	for counter := 0; len(out) < dataLen; counter++ {
		state := [16]uint32{
			chachaSalsaConst0, chachaSalsaConst1, chachaSalsaConst2, chachaSalsaConst3,
			le32(key[0:4]), le32(key[4:8]), le32(key[8:12]), le32(key[12:16]),
			le32(key[16:20]), le32(key[20:24]), le32(key[24:28]), le32(key[28:32]),
			uint32(counter), 0,
			le32(nonce[0:4]), le32(nonce[4:8]),
		}
		initial := state
		for rd := 0; rd < rounds/2; rd++ {
			chachaColumn(&state)
			chachaRow(&state)
		}
		block := make([]byte, 0, blockSize)
		for i := 0; i < 16; i++ {
			w := state[i] + initial[i]
			block = append(block, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
		}
		out = append(out, block...)
	}
	return out
}

func chachaColumn(state *[16]uint32) {
	s := state[:]
	chachaQuarterRound(s, 0, 4, 8, 12)
	chachaQuarterRound(s, 1, 5, 9, 13)
	chachaQuarterRound(s, 2, 6, 10, 14)
	chachaQuarterRound(s, 3, 7, 11, 15)
}

func chachaRow(state *[16]uint32) {
	s := state[:]
	chachaQuarterRound(s, 0, 5, 10, 15)
	chachaQuarterRound(s, 1, 6, 11, 12)
	chachaQuarterRound(s, 2, 7, 8, 13)
	chachaQuarterRound(s, 3, 4, 9, 14)
}

// salsaKeystream generates the keystream blocks for Salsa20.
func salsaKeystream(key, nonce []byte, rounds int, dataLen int) []byte {
	const blockSize = 64
	out := make([]byte, 0, dataLen)
	for blockCounter := 0; len(out) < dataLen; blockCounter++ {
		state := [16]uint32{
			chachaSalsaConst0, le32(key[0:4]), le32(key[4:8]), le32(key[8:12]),
			le32(key[12:16]), chachaSalsaConst1,
			le32(nonce[0:4]), le32(nonce[4:8]),
			uint32(blockCounter), 0,
			chachaSalsaConst2, le32(key[16:20]),
			le32(key[20:24]), le32(key[24:28]), le32(key[28:32]), chachaSalsaConst3,
		}
		initial := state
		for rd := 0; rd < rounds/2; rd++ {
			salsaColumn(&state)
			salsaRow(&state)
		}
		block := make([]byte, 0, blockSize)
		for i := 0; i < 16; i++ {
			w := state[i] + initial[i]
			block = append(block, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
		}
		out = append(out, block...)
	}
	return out
}

func salsaColumn(state *[16]uint32) {
	s := state[:]
	salsaQuarterRound(s, 0, 4, 8, 12)
	salsaQuarterRound(s, 5, 9, 13, 1)
	salsaQuarterRound(s, 10, 14, 2, 6)
	salsaQuarterRound(s, 15, 3, 7, 11)
}

func salsaRow(state *[16]uint32) {
	s := state[:]
	salsaQuarterRound(s, 0, 1, 2, 3)
	salsaQuarterRound(s, 5, 6, 7, 4)
	salsaQuarterRound(s, 10, 11, 8, 9)
	salsaQuarterRound(s, 15, 12, 13, 14)
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// ChaCha20Encode encrypts s, hashing the key to 32 bytes and deriving a
// deterministic nonce. Output is hex.
func ChaCha20Encode(s, key string) string {
	data := []byte(s)
	k := chachaSalsaPrepareKey(key)
	nonce := chachaSalsaNonce(k)
	ks := chachaKeystream(k, nonce, 20, len(data))
	for i := range data {
		data[i] ^= ks[i]
	}
	return hex.EncodeToString(data)
}

// ChaCha20Decode reverses ChaCha20Encode.
func ChaCha20Decode(hexStr, key string) (string, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	k := chachaSalsaPrepareKey(key)
	nonce := chachaSalsaNonce(k)
	ks := chachaKeystream(k, nonce, 20, len(data))
	for i := range data {
		data[i] ^= ks[i]
	}
	return string(data), nil
}

// Salsa20Encode encrypts s (Salsa20/20).
func Salsa20Encode(s, key string) string {
	data := []byte(s)
	k := chachaSalsaPrepareKey(key)
	nonce := chachaSalsaNonce(k)
	ks := salsaKeystream(k, nonce, 20, len(data))
	for i := range data {
		data[i] ^= ks[i]
	}
	return hex.EncodeToString(data)
}

// Salsa20Decode reverses Salsa20Encode.
func Salsa20Decode(hexStr, key string) (string, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	k := chachaSalsaPrepareKey(key)
	nonce := chachaSalsaNonce(k)
	ks := salsaKeystream(k, nonce, 20, len(data))
	for i := range data {
		data[i] ^= ks[i]
	}
	return string(data), nil
}