// internal/cipher/polygraphic_more.go
//
// Two-Square, Four-Square, and Polybius ciphers. These extend the
// digraphic/grid-based cipher family already started by Playfair in
// polygraphic.go. Two-Square uses two keyed 5x5 matrices, Four-Square
// uses four (two keyed, two standard), and Polybius uses a 5x5 grid
// to encode each letter as a pair of row/column digits.
package cipher

import (
	"strings"
)

// --- Two-Square ---

// twoSquareMatrix builds a single 5x5 keyed matrix (J merged into I)
// from a keyword, reusing the same logic as Playfair.
func twoSquareMatrix(key string) [][]byte {
	return playfairMatrix(key)
}

func twoSquarePositions(m [][]byte) [26][2]int {
	return playfairPositions(m)
}

func twoSquareLookup(m [][]byte, r, c int) byte {
	return playfairLookup(m, r, c)
}

// TwoSquareEncode encrypts s using two keyed 5x5 matrices derived from
// key (split in half: first half → top matrix, second half → bottom).
func TwoSquareEncode(s, key string) string {
	topM, botM := twoSquareSplitKey(key)
	topPos := twoSquarePositions(topM)
	botPos := twoSquarePositions(botM)
	text := playfairPrepare(s)
	var b strings.Builder
	for i := 0; i+1 < len(text); i += 2 {
		a, c := text[i], text[i+1]
		pa := topPos[a-'A']
		pc := botPos[c-'A']
		b.WriteByte(twoSquareLookup(topM, pa[0], pc[1]))
		b.WriteByte(twoSquareLookup(botM, pc[0], pa[1]))
	}
	return b.String()
}

// TwoSquareDecode reverses TwoSquareEncode.
func TwoSquareDecode(s, key string) string {
	topM, botM := twoSquareSplitKey(key)
	topPos := twoSquarePositions(topM)
	botPos := twoSquarePositions(botM)
	text := playfairCleanText(s)
	var b strings.Builder
	for i := 0; i+1 < len(text); i += 2 {
		a, c := text[i], text[i+1]
		// Encode wrote A' = topM[rowA][colC] and C' = botM[rowC][colA],
		// so A' sits in the top matrix at (rowA, colC) and C' in the
		// bottom at (rowC, colA). Recover A from topM[rowA][colA] and
		// C from botM[rowC][colC].
		pa := topPos[a-'A'] // (rowA, colC)
		pc := botPos[c-'A'] // (rowC, colA)
		b.WriteByte(twoSquareLookup(topM, pa[0], pc[1])) // topM[rowA][colA]
		b.WriteByte(twoSquareLookup(botM, pc[0], pa[1])) // botM[rowC][colC]
	}
	return cleanPlayfairPadding(b.String())
}

func twoSquareSplitKey(key string) (top, bot [][]byte) {
	clean := strings.ToUpper(strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' && r != 'J' {
			return r
		}
		return -1
	}, key))
	half := len(clean) / 2
	keyTop := clean[:half]
	keyBot := clean[half:]
	if half == 0 {
		// Mirrors the reference exactly: with a 0/1-char key, the top
		// matrix takes the (empty or single) key and the bottom gets
		// the key plus "EXTRA".
		keyTop = clean
		keyBot = clean + "EXTRA"
	}
	return twoSquareMatrix(keyTop), twoSquareMatrix(keyBot)
}

// --- Four-Square ---

// FourSquareEncode encrypts using four 5x5 matrices. The key can be
// comma-separated ("KEY1,KEY2") or a single string split in half.
func FourSquareEncode(s, key string) string {
	tl, tr, bl, br := fourSquareMatrices(key)
	tlPos := twoSquarePositions(tl)
	brPos := twoSquarePositions(br)
	text := playfairPrepare(s)
	var b strings.Builder
	for i := 0; i+1 < len(text); i += 2 {
		a, c := text[i], text[i+1]
		pa := tlPos[a-'A']
		pc := brPos[c-'A']
		b.WriteByte(twoSquareLookup(tr, pa[0], pc[1]))
		b.WriteByte(twoSquareLookup(bl, pc[0], pa[1]))
	}
	return b.String()
}

// FourSquareDecode reverses FourSquareEncode.
func FourSquareDecode(s, key string) string {
	tl, tr, bl, br := fourSquareMatrices(key)
	trPos := twoSquarePositions(tr)
	blPos := twoSquarePositions(bl)
	text := playfairCleanText(s)
	var b strings.Builder
	for i := 0; i+1 < len(text); i += 2 {
		a, c := text[i], text[i+1]
		// Encode wrote A' = tr[rowA][colC] and C' = bl[rowC][colA], so
		// A' sits in tr at (rowA, colC) and C' in bl at (rowC, colA).
		// Recover A from tl[rowA][colA] and C from br[rowC][colC].
		pa := trPos[a-'A'] // (rowA, colC)
		pc := blPos[c-'A'] // (rowC, colA)
		b.WriteByte(twoSquareLookup(tl, pa[0], pc[1])) // tl[rowA][colA]
		b.WriteByte(twoSquareLookup(br, pc[0], pa[1])) // br[rowC][colC]
	}
	return cleanPlayfairPadding(b.String())
}

func fourSquareMatrices(key string) (tl, tr, bl, br [][]byte) {
	key1, key2, _ := strings.Cut(key, ",")
	key1 = strings.TrimSpace(key1)
	key2 = strings.TrimSpace(key2)
	if key1 == "" {
		key1 = key
	}
	if key2 == "" {
		key2 = key + "EXTRA"
	}
	// tl and br are standard (unkeyed) alphabet
	std := twoSquareMatrix("")
	tr = twoSquareMatrix(key1)
	bl = twoSquareMatrix(key2)
	br = std
	return std, tr, bl, std
}

// --- Polybius ---

// polybiusStandard is the standard 5x5 Polybius square (J merged into I,
// digits 1-5 for row/column).
const polybiusStandard = "ABCDEFGHIKLMNOPQRSTUVWXYZ" // 25 letters

// PolybiusEncode encodes s as row-column digit pairs using the standard
// 5x5 square. Output is digit pairs separated by spaces (e.g. "23 15 31 31 34"
// for "HELLO"). If key is non-empty, a keyed square is used instead.
func PolybiusEncode(s, key string) string {
	grid := polybiusGrid(key)
	pos := [26][2]int{}
	for r := 0; r < 5; r++ {
		for c := 0; c < 5; c++ {
			ch := grid[r*5+c]
			if ch >= 'A' && ch <= 'Z' {
				pos[ch-'A'] = [2]int{r + 1, c + 1}
			}
		}
	}
	var b strings.Builder
	first := true
	for _, r := range strings.ToUpper(s) {
		if r == 'J' {
			r = 'I'
		}
		if r >= 'A' && r <= 'Z' {
			if !first {
				b.WriteByte(' ')
			}
			b.WriteByte(byte('0' + pos[r-'A'][0]))
			b.WriteByte(byte('0' + pos[r-'A'][1]))
			first = false
		}
	}
	return b.String()
}

// PolybiusDecode decodes space-separated or concatenated digit pairs.
func PolybiusDecode(s, key string) string {
	grid := polybiusGrid(key)
	// Normalize: strip everything that isn't a digit.
	var digits []byte
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, byte(r))
		}
	}
	if len(digits)%2 != 0 {
		return s // malformed
	}
	var b strings.Builder
	for i := 0; i+1 < len(digits); i += 2 {
		row := int(digits[i] - '1')
		col := int(digits[i+1] - '1')
		if row < 0 || row > 4 || col < 0 || col > 4 {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(grid[row*5+col])
	}
	return b.String()
}

func polybiusGrid(key string) [25]byte {
	key = strings.ToUpper(strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' && r != 'J' {
			return r
		}
		return -1
	}, key))
	seen := [26]bool{}
	var letters []byte
	for i := 0; i < len(key); i++ {
		ch := key[i]
		if !seen[ch-'A'] {
			seen[ch-'A'] = true
			letters = append(letters, ch)
		}
	}
	for ch := byte('A'); ch <= 'Z'; ch++ {
		if ch == 'J' {
			continue
		}
		if !seen[ch-'A'] {
			seen[ch-'A'] = true
			letters = append(letters, ch)
		}
	}
	var grid [25]byte
	copy(grid[:], letters)
	return grid
}
