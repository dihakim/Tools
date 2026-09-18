// internal/cipher/route_cipher.go
//
// Route cipher: a transposition cipher that writes text into a grid
// row-by-row and then reads it out in a spiral pattern (clockwise or
// counter-clockwise, from one of the four corners). Decryption reverses
// the process. The "key" for this cipher is the grid configuration, so
// the key string either names a variant ("clockwise" / "counter-clockwise")
// or is used as a seed. Like the Python reference, the default behaviour
// uses a value-encoded rows/cols that decode the grid geometry.
package cipher

import (
	"strconv"
	"strings"
)

// routeDirectionPattern returns movement vectors for a spiral direction +
// start corner, matching the Python reference's _get_direction_pattern.
// dirs[row] is the order of (dr, dc) movements to follow.
func routeDirectionPattern(direction, start string) [][2]int {
	switch direction {
	case "clockwise":
		switch start {
		case "top-right":
			return [][2]int{{0, -1}, {1, 0}, {0, 1}, {-1, 0}} // left, down, right, up
		case "bottom-left":
			return [][2]int{{0, 1}, {-1, 0}, {0, -1}, {1, 0}} // right, up, left, down
		case "bottom-right":
			return [][2]int{{0, -1}, {-1, 0}, {0, 1}, {1, 0}} // left, up, right, down
		default: // top-left
			return [][2]int{{0, 1}, {1, 0}, {0, -1}, {-1, 0}} // right, down, left, up
		}
	default: // counter-clockwise
		switch start {
		case "top-right":
			return [][2]int{{1, 0}, {0, -1}, {-1, 0}, {0, 1}} // down, left, up, right
		case "bottom-left":
			return [][2]int{{-1, 0}, {0, 1}, {1, 0}, {0, -1}} // up, right, down, left
		case "bottom-right":
			return [][2]int{{-1, 0}, {0, -1}, {1, 0}, {0, 1}} // up, left, down, right
		default: // top-left
			return [][2]int{{1, 0}, {0, 1}, {-1, 0}, {0, -1}} // down, right, up, left
		}
	}
}

// routeStartPosition returns the (row, col) of the chosen start corner.
func routeStartPosition(rows, cols int, start string) (int, int) {
	switch start {
	case "top-right":
		return 0, cols - 1
	case "bottom-left":
		return rows - 1, 0
	case "bottom-right":
		return rows - 1, cols - 1
	default: // top-left
		return 0, 0
	}
}

// routeSpiralOrder computes the sequence of (row, col) coordinates
// visited in the spiral, given grid dimensions, direction and start.
func routeSpiralOrder(rows, cols int, direction, start string) [][2]int {
	if rows <= 0 || cols <= 0 {
		return nil
	}
	visited := make([][]bool, rows)
	for i := range visited {
		visited[i] = make([]bool, cols)
	}
	dirs := routeDirectionPattern(direction, start)
	row, col := routeStartPosition(rows, cols, start)
	dirIdx := 0
	order := make([][2]int, 0, rows*cols)
	for k := 0; k < rows*cols; k++ {
		if row < 0 || row >= rows || col < 0 || col >= cols {
			break
		}
		order = append(order, [2]int{row, col})
		visited[row][col] = true
		// Try to move in current direction.
		nextRow := row + dirs[dirIdx][0]
		nextCol := col + dirs[dirIdx][1]
		// If blocked, change direction.
		if nextRow < 0 || nextRow >= rows || nextCol < 0 || nextCol >= cols || visited[nextRow][nextCol] {
			dirIdx = (dirIdx + 1) % 4
			nextRow = row + dirs[dirIdx][0]
			nextCol = col + dirs[dirIdx][1]
		}
		row, col = nextRow, nextCol
	}
	return order
}

// routeCleanText uppercases and removes spaces (matching the Python
// reference's remove_spaces=True default).
func routeCleanText(s string) string {
	return strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s))
}

// RouteEncode encrypts s using a spiral route cipher. key encodes the
// grid geometry: "<rows>x<cols>_<direction>_<start>" (e.g. "4x4_clockwise_top-left").
// If the key doesn't match that format, a default 4x4 clockwise top-left
// grid is used.
func RouteEncode(s, key string) string {
	rows, cols, direction, start := routeParseKey(key)
	text := routeCleanText(s)
	if text == "" {
		return ""
	}
	gridSize := rows * cols
	for len(text) < gridSize {
		text += "X"
	}
	text = text[:gridSize]
	grid := make([][]byte, rows)
	for i := range grid {
		grid[i] = make([]byte, cols)
	}
	for i := 0; i < rows*cols; i++ {
		grid[i/cols][i%cols] = text[i]
	}
	order := routeSpiralOrder(rows, cols, direction, start)
	var b strings.Builder
	for _, p := range order {
		b.WriteByte(grid[p[0]][p[1]])
	}
	return b.String()
}

// RouteDecode decrypts a route cipher given the grid configuration in key.
func RouteDecode(s, key string) string {
	rows, cols, direction, start := routeParseKey(key)
	text := routeCleanText(s)
	if text == "" {
		return ""
	}
	gridSize := rows * cols
	for len(text) < gridSize {
		text += "X"
	}
	text = text[:gridSize]
	// Fill the grid by following the spiral order with the ciphertext.
	grid := make([][]byte, rows)
	for i := range grid {
		grid[i] = make([]byte, cols)
	}
	order := routeSpiralOrder(rows, cols, direction, start)
	for i, p := range order {
		if i < len(text) {
			grid[p[0]][p[1]] = text[i]
		}
	}
	// Read row by row to recover the plaintext.
	var b strings.Builder
	for i := 0; i < rows*cols; i++ {
		b.WriteByte(grid[i/cols][i%cols])
	}
	plain := b.String()
	// Remove padding (trailing X) - keep it minimal, matching the
	// reference's _remove_padding.
	plain = strings.TrimSuffix(plain, "X")
	return plain
}

// routeParseKey parses the key into grid geometry. Format:
// "<rows>x<cols>_<direction>_<start>". Falls back to 4x4/clockwise/top-left.
func routeParseKey(key string) (rows, cols int, direction, start string) {
	rows, cols = 4, 4
	direction, start = "clockwise", "top-left"
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	// Try to parse the "RxC_direction_start" form.
	parts := strings.SplitN(key, "_", 3)
	if len(parts) >= 1 {
		dim := strings.SplitN(parts[0], "x", 2)
		if len(dim) == 2 {
			if r, err := strconv.Atoi(dim[0]); err == nil && r >= 1 {
				rows = r
			}
			if c, err := strconv.Atoi(dim[1]); err == nil && c >= 1 {
				cols = c
			}
		}
	}
	if len(parts) >= 2 {
		switch parts[1] {
		case "counter-clockwise", "counterclockwise":
			direction = "counter-clockwise"
		default:
			direction = "clockwise"
		}
	}
	if len(parts) >= 3 {
		switch parts[2] {
		case "top-right", "bottom-left", "bottom-right":
			start = parts[2]
		default:
			start = "top-left"
		}
	}
	return
}

// routeConfigs tries all possible grid geometries up to maxDim that fit
// the text length, returning the (rows, cols, direction, start) configs
// the Python reference would try (exact divisors + common grids).
func routeConfigs(textLen, maxDim int) [][4]string {
	var configs [][4]string
	for rows := 2; rows <= maxDim; rows++ {
		if textLen%rows == 0 {
			cols := textLen / rows
			if cols >= 1 {
				configs = append(configs, [4]string{strconv.Itoa(rows), strconv.Itoa(cols), "clockwise", "top-left"})
			}
		}
	}
	common := [][2]int{{2, 2}, {3, 3}, {4, 4}, {5, 5}, {6, 6}, {2, 3}, {3, 4}, {4, 5}, {5, 6}, {3, 2}, {4, 3}, {5, 4}, {6, 5}}
	for _, c := range common {
		if c[0]*c[1] >= textLen && c[0] <= maxDim && c[1] <= maxDim {
			configs = append(configs, [4]string{strconv.Itoa(c[0]), strconv.Itoa(c[1]), "clockwise", "top-left"})
		}
	}
	// Deduplicate.
	seen := map[[4]string]bool{}
	var out [][4]string
	for _, c := range configs {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}