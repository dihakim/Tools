// internal/sqlitemin/btree.go
package sqlitemin

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	pageTypeInteriorIndex = 0x02
	pageTypeInteriorTable = 0x05
	pageTypeLeafIndex     = 0x0a
	pageTypeLeafTable     = 0x0d
)

// walkTableBTree visits every row in a table B-tree rooted at pageNum, in
// key order, calling visit(rowid, columnValues) for each. Stops early if
// visit returns false. Page 1 is a special case: its first 100 bytes are
// the file header, so the B-tree page data there starts at offset 100.
func (db *DB) walkTableBTree(pageNum int, visit func(rowid int64, values []any) bool) error {
	stop := false
	err := db.walkPage(pageNum, func(rowid int64, payload []byte) error {
		if stop {
			return nil
		}
		values, err := decodeRecord(payload)
		if err != nil {
			return nil // skip a corrupt/unparseable row rather than aborting the whole table
		}
		if !visit(rowid, values) {
			stop = true
		}
		return nil
	})
	return err
}

func (db *DB) walkPage(pageNum int, onRow func(rowid int64, payload []byte) error) error {
	raw, err := db.readPage(pageNum)
	if err != nil {
		return err
	}
	page := raw
	headerOffset := 0
	if pageNum == 1 {
		headerOffset = 100
	}
	if headerOffset >= len(page) {
		return fmt.Errorf("page %d too small", pageNum)
	}
	pageType := page[headerOffset]

	var cellCount int
	var cellPointerArrayStart int
	switch pageType {
	case pageTypeLeafTable:
		cellCount = int(binary.BigEndian.Uint16(page[headerOffset+3 : headerOffset+5]))
		cellPointerArrayStart = headerOffset + 8
	case pageTypeInteriorTable:
		cellCount = int(binary.BigEndian.Uint16(page[headerOffset+3 : headerOffset+5]))
		cellPointerArrayStart = headerOffset + 12
	default:
		// Index B-tree pages, or something unexpected - not used by ReadTable
		// (which only walks table B-trees reached via a table's rootpage).
		return fmt.Errorf("unsupported page type 0x%02x on page %d", pageType, pageNum)
	}

	for i := 0; i < cellCount; i++ {
		ptrOff := cellPointerArrayStart + i*2
		if ptrOff+2 > len(page) {
			break
		}
		cellOffset := int(binary.BigEndian.Uint16(page[ptrOff : ptrOff+2]))
		if cellOffset >= len(page) {
			continue
		}

		if pageType == pageTypeInteriorTable {
			// Interior cell: 4-byte left-child page number, then a varint rowid
			// (rowid itself unused here - we just need to recurse into the child).
			if cellOffset+4 > len(page) {
				continue
			}
			childPage := int(binary.BigEndian.Uint32(page[cellOffset : cellOffset+4]))
			if err := db.walkPage(childPage, onRow); err != nil {
				return err
			}
			continue
		}

		// Leaf table cell: varint payload length, varint rowid, payload bytes
		// (possibly spilling into overflow pages).
		payloadLen, n1 := readVarint(page[cellOffset:])
		rowid, n2 := readVarint(page[cellOffset+n1:])
		payloadStart := cellOffset + n1 + n2

		payload, err := db.readPayload(page, payloadStart, int(payloadLen))
		if err != nil {
			continue // skip this row rather than failing the whole page
		}
		if err := onRow(rowid, payload); err != nil {
			return err
		}
	}

	// After an interior page's numbered cells, there's one more child pointer
	// (the "right-most pointer") covering keys greater than all cells' keys.
	if pageType == pageTypeInteriorTable {
		rightMost := int(binary.BigEndian.Uint32(page[headerOffset+8 : headerOffset+12]))
		if err := db.walkPage(rightMost, onRow); err != nil {
			return err
		}
	}

	return nil
}

// readPayload extracts a cell's payload starting at offset within page,
// following overflow pages if the payload doesn't fit locally. Uses the
// standard SQLite table-leaf overflow threshold calculation.
func (db *DB) readPayload(page []byte, offset int, totalLen int) ([]byte, error) {
	usable := db.pageSize // no reserved-space region assumed (byte 20 of header, uncommon to be nonzero)
	maxLocal := usable - 35
	if totalLen <= maxLocal {
		if offset+totalLen > len(page) {
			return nil, fmt.Errorf("payload exceeds page bounds")
		}
		return page[offset : offset+totalLen], nil
	}

	minLocal := (usable-12)*32/255 - 23
	k := minLocal + (totalLen-minLocal)%(usable-4)
	localLen := minLocal
	if k <= maxLocal {
		localLen = k
	}

	if offset+localLen+4 > len(page) {
		return nil, fmt.Errorf("payload header exceeds page bounds")
	}
	result := make([]byte, 0, totalLen)
	result = append(result, page[offset:offset+localLen]...)
	nextOverflow := int(binary.BigEndian.Uint32(page[offset+localLen : offset+localLen+4]))

	remaining := totalLen - localLen
	for nextOverflow != 0 && remaining > 0 {
		opage, err := db.readPage(nextOverflow)
		if err != nil {
			return nil, err
		}
		if len(opage) < 4 {
			break
		}
		next := int(binary.BigEndian.Uint32(opage[0:4]))
		chunk := opage[4:]
		take := len(chunk)
		if take > remaining {
			take = remaining
		}
		result = append(result, chunk[:take]...)
		remaining -= take
		nextOverflow = next
	}
	return result, nil
}

// readVarint decodes a SQLite variable-length integer (big-endian, 7 bits
// per byte, up to 9 bytes) and returns (value, bytesConsumed).
func readVarint(b []byte) (int64, int) {
	var result int64
	for i := 0; i < 8 && i < len(b); i++ {
		result = (result << 7) | int64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return result, i + 1
		}
	}
	if len(b) > 8 {
		result = (result << 8) | int64(b[8])
	}
	return result, 9
}

// decodeRecord decodes a SQLite record (row payload): a varint header
// length, then a varint serial type per column, then the column values
// packed back-to-back per the serial type encoding.
func decodeRecord(payload []byte) ([]any, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	headerLen, n := readVarint(payload)
	if int(headerLen) > len(payload) || headerLen < 0 {
		return nil, fmt.Errorf("bad header length")
	}

	var serialTypes []int64
	pos := n
	for pos < int(headerLen) {
		st, k := readVarint(payload[pos:])
		serialTypes = append(serialTypes, st)
		pos += k
	}

	values := make([]any, 0, len(serialTypes))
	bodyPos := int(headerLen)
	for _, st := range serialTypes {
		v, size, err := decodeValue(payload, bodyPos, st)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
		bodyPos += size
	}
	return values, nil
}

func decodeValue(payload []byte, pos int, serialType int64) (any, int, error) {
	switch {
	case serialType == 0:
		return nil, 0, nil // NULL
	case serialType == 1:
		return readIntN(payload, pos, 1), 1, nil
	case serialType == 2:
		return readIntN(payload, pos, 2), 2, nil
	case serialType == 3:
		return readIntN(payload, pos, 3), 3, nil
	case serialType == 4:
		return readIntN(payload, pos, 4), 4, nil
	case serialType == 5:
		return readIntN(payload, pos, 5), 5, nil
	case serialType == 6:
		return readIntN(payload, pos, 8), 8, nil
	case serialType == 7:
		if pos+8 > len(payload) {
			return nil, 0, fmt.Errorf("float out of bounds")
		}
		bits := binary.BigEndian.Uint64(payload[pos : pos+8])
		return math.Float64frombits(bits), 8, nil
	case serialType == 8:
		return int64(0), 0, nil
	case serialType == 9:
		return int64(1), 0, nil
	case serialType >= 12 && serialType%2 == 0:
		size := int((serialType - 12) / 2)
		if pos+size > len(payload) {
			return nil, 0, fmt.Errorf("blob out of bounds")
		}
		blob := make([]byte, size)
		copy(blob, payload[pos:pos+size])
		return blob, size, nil
	case serialType >= 13 && serialType%2 == 1:
		size := int((serialType - 13) / 2)
		if pos+size > len(payload) {
			return nil, 0, fmt.Errorf("text out of bounds")
		}
		return string(payload[pos : pos+size]), size, nil
	default:
		return nil, 0, nil
	}
}

// readIntN reads an n-byte big-endian signed integer (SQLite's fixed-width
// integer serial types are sign-extended from n bytes, n in 1..8).
func readIntN(b []byte, pos, n int) int64 {
	if pos+n > len(b) {
		return 0
	}
	var v int64
	if b[pos]&0x80 != 0 {
		v = -1 // sign-extend
	}
	for i := 0; i < n; i++ {
		v = (v << 8) | int64(b[pos+i])
	}
	return v
}
