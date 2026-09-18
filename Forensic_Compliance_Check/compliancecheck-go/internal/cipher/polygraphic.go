// internal/cipher/polygraphic.go
//
// Playfair - the classic digraphic cipher, encrypting letters two at a
// time using a keyed 5x5 matrix (J merged with I). Unlike the shift and
// polyalphabetic ciphers here it is purely keyed: the matrix depends on
// the keyword in a way that makes keyless recovery impractical (the
// reference implementation doesn't even attempt auto-solve), so no crack
// path exists for it - exactly like the Python source it mirrors.
package cipher

import "strings"

// playfairCleanText uppercases and keeps only A-Z, mapping J to I (the
// standard Playfair merge - the matrix has no J).
func playfairCleanText(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r >= 'A' && r <= 'Z' && r != 'J':
			b.WriteRune(r)
		case r == 'J':
			b.WriteRune('I')
		}
	}
	return b.String()
}

// playfairPrepare applies Playfair's two layout rules to a cleaned text:
// pad with X to even length, then split any double letter in a pair by
// inserting X between the copies (BALLOON -> BALXLOON), re-padding if
// that leaves a dangling final letter.
func playfairPrepare(s string) string {
	text := playfairCleanText(s)
	if len(text)%2 == 1 {
		text += "X"
	}
	var b strings.Builder
	i := 0
	for i < len(text) {
		a := text[i]
		if i+1 < len(text) {
			if text[i+1] == a {
				b.WriteByte(a)
				b.WriteByte('X')
				i++
			} else {
				b.WriteByte(a)
				b.WriteByte(text[i+1])
				i += 2
			}
		} else {
			b.WriteByte(a)
			i++
		}
	}
	out := b.String()
	if len(out)%2 == 1 {
		out += "X"
	}
	return out
}

// playfairMatrix builds the 5x5 keyed matrix: the deduplicated keyword
// (J merged into I) first, then the remaining alphabet in order.
func playfairMatrix(key string) [][]byte {
	var ordered []byte
	seen := [26]bool{}
	for _, r := range strings.ToUpper(key) {
		ch := byte(r)
		if ch == 'J' {
			ch = 'I'
		}
		if ch < 'A' || ch > 'Z' || seen[ch-'A'] {
			continue
		}
		seen[ch-'A'] = true
		ordered = append(ordered, ch)
	}
	for ch := byte('A'); ch <= 'Z'; ch++ {
		if ch == 'J' || seen[ch-'A'] {
			continue
		}
		seen[ch-'A'] = true
		ordered = append(ordered, ch)
	}
	matrix := make([][]byte, 5)
	for r := 0; r < 5; r++ {
		matrix[r] = ordered[r*5 : r*5+5]
	}
	return matrix
}

// playfairPositions precomputes each letter's (row, col) once per matrix.
// Indexed by letter-'A' over the full alphabet: J is never stored (the
// matrix omits it) but is still a valid index that is simply never read,
// because cleaned input folds J into I.
func playfairPositions(matrix [][]byte) [26][2]int {
	var pos [26][2]int
	for r := 0; r < 5; r++ {
		for c := 0; c < 5; c++ {
			pos[matrix[r][c]-'A'] = [2]int{r, c}
		}
	}
	return pos
}

func playfairLookup(matrix [][]byte, r, c int) byte {
	return matrix[((r%5)+5)%5][((c%5)+5)%5]
}

// PlayfairEncode encrypts s with the given keyword using the standard rules.
func PlayfairEncode(s, key string) string {
	matrix := playfairMatrix(key)
	pos := playfairPositions(matrix)
	text := playfairPrepare(s)
	var b strings.Builder
	for i := 0; i+1 < len(text); i += 2 {
		a, c := text[i], text[i+1]
		pa, pc := pos[a-'A'], pos[c-'A']
		ra, ca := pa[0], pa[1]
		rb, cb := pc[0], pc[1]
		switch {
		case ra == rb:
			b.WriteByte(playfairLookup(matrix, ra, ca+1))
			b.WriteByte(playfairLookup(matrix, rb, cb+1))
		case ca == cb:
			b.WriteByte(playfairLookup(matrix, ra+1, ca))
			b.WriteByte(playfairLookup(matrix, rb+1, cb))
		default:
			b.WriteByte(playfairLookup(matrix, ra, cb))
			b.WriteByte(playfairLookup(matrix, rb, ca))
		}
	}
	return b.String()
}

// PlayfairDecode decrypts s with the same keyword and strips structurally
// obvious padding: trailing/leading X, and X wedged between two consonants
// (heuristic cleanup mirroring the reference implementation's approach;
// a legitimate X between vowels is preserved).
func PlayfairDecode(s, key string) string {
	matrix := playfairMatrix(key)
	pos := playfairPositions(matrix)
	text := playfairCleanText(s)
	var b strings.Builder
	for i := 0; i+1 < len(text); i += 2 {
		a, c := text[i], text[i+1]
		pa, pc := pos[a-'A'], pos[c-'A']
		ra, ca := pa[0], pa[1]
		rb, cb := pc[0], pc[1]
		switch {
		case ra == rb:
			b.WriteByte(playfairLookup(matrix, ra, ca-1))
			b.WriteByte(playfairLookup(matrix, rb, cb-1))
		case ca == cb:
			b.WriteByte(playfairLookup(matrix, ra-1, ca))
			b.WriteByte(playfairLookup(matrix, rb-1, cb))
		default:
			b.WriteByte(playfairLookup(matrix, ra, cb))
			b.WriteByte(playfairLookup(matrix, rb, ca))
		}
	}
	return cleanPlayfairPadding(b.String())
}

// cleanPlayfairPadding removes filler X that Playfair unavoidably inserts:
// trailing (the pad character), leading, and any X between two consonants
// (that's how padding is almost always dropped in practice - a doubled
// letter gets "LX" inserted by the prepare step, still wedged between
// consonants). Vowel-adjacent X is kept, since it may be genuine text.
func cleanPlayfairPadding(text string) string {
	trimmed := strings.Trim(text, "X")
	var b strings.Builder
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		if ch == 'X' && i > 0 && i < len(trimmed)-1 && isPlayfairConsonant(trimmed[i-1]) && isPlayfairConsonant(trimmed[i+1]) {
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func isPlayfairConsonant(ch byte) bool {
	return ch >= 'A' && ch <= 'Z' && ch != 'A' && ch != 'E' && ch != 'I' && ch != 'O' && ch != 'U' && ch != 'Y'
}