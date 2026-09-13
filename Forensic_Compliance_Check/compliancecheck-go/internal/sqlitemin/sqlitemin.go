// internal/sqlitemin/sqlitemin.go
//
// A minimal, dependency-free SQLite file reader. This is NOT a SQL engine
// - no query parsing, no indexes, no joins, no write support. It does
// exactly one thing: given a table name, walk that table's B-tree and
// decode its rows into column-name-keyed maps. That's all browser
// history/bookmark reading needs (fixed, known tables), and it keeps this
// project's zero-third-party-dependency architecture intact - a real
// pure-Go SQLite driver was attempted first, but its own transitive
// dependencies (golang.org/x/sys, modernc.org/libc) turned out to be
// unreachable from this project's sandboxed network, which forced this
// approach - which, on reflection, is the better outcome anyway for a
// single-static-binary forensics tool.
//
// Format reference: the SQLite file format is public and stable
// (https://www.sqlite.org/fileformat2.html). This implements: the file
// header (page size), table B-tree traversal (interior + leaf pages),
// record decoding (varint header + serial-type-encoded columns), and
// overflow page following for oversized fields. It does NOT implement:
// WAL-file merging (a database with pending WAL-mode writes may appear
// slightly stale - a real limitation worth knowing, not silently
// papered over), freelist handling, or index B-trees (unneeded, since
// tables are read directly by root page, not via index lookup).
package sqlitemin

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

type DB struct {
	f        *os.File
	pageSize int
}

func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 100)
	if _, err := f.ReadAt(header, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("reading header: %w", err)
	}
	if string(header[0:16]) != "SQLite format 3\x00" {
		f.Close()
		return nil, fmt.Errorf("not a SQLite file (bad magic)")
	}
	pageSize := int(binary.BigEndian.Uint16(header[16:18]))
	if pageSize == 1 {
		pageSize = 65536 // 1 is the on-disk encoding for the max page size
	}
	if pageSize < 512 {
		f.Close()
		return nil, fmt.Errorf("implausible page size %d", pageSize)
	}
	return &DB{f: f, pageSize: pageSize}, nil
}

func (db *DB) Close() error { return db.f.Close() }

func (db *DB) readPage(pageNum int) ([]byte, error) {
	buf := make([]byte, db.pageSize)
	off := int64(pageNum-1) * int64(db.pageSize)
	n, err := db.f.ReadAt(buf, off)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// tableInfo from sqlite_master.
type tableInfo struct {
	rootPage      int
	columns       []string
	rowidAliasIdx int // index of the INTEGER PRIMARY KEY column, or -1 if none
}

// ReadTable returns up to maxRows rows from the named table, as
// column-name-keyed maps. Column order/names are read dynamically from
// the table's own CREATE TABLE statement (via sqlite_master), not
// hardcoded - real Firefox/Chrome schemas vary across versions, so this
// stays correct across those variations rather than assuming fixed
// column positions.
func (db *DB) ReadTable(tableName string, maxRows int) ([]map[string]any, error) {
	info, err := db.findTable(tableName)
	if err != nil {
		return nil, err
	}

	var rows []map[string]any
	err = db.walkTableBTree(info.rootPage, func(rowid int64, values []any) bool {
		row := map[string]any{"rowid": rowid}
		for i, col := range info.columns {
			if i < len(values) {
				row[col] = values[i]
			}
		}
		// SQLite stores an INTEGER PRIMARY KEY column as a rowid alias - its
		// value is NEVER in the record body (decodes as NULL), the true value
		// IS the rowid. Verified against a real SQLite file during testing:
		// without this fix, every "id" column read back as nil.
		if info.rowidAliasIdx >= 0 && info.rowidAliasIdx < len(info.columns) {
			row[info.columns[info.rowidAliasIdx]] = rowid
		}
		rows = append(rows, row)
		return len(rows) < maxRows
	})
	return rows, err
}

// findTable reads page 1's sqlite_master table (always rooted at page 1
// itself, per the SQLite format) to find the target table's root page and
// column list.
func (db *DB) findTable(tableName string) (tableInfo, error) {
	var found *tableInfo
	err := db.walkTableBTree(1, func(rowid int64, values []any) bool {
		// sqlite_master columns are always: type, name, tbl_name, rootpage, sql
		if len(values) < 5 {
			return true
		}
		typ, _ := values[0].(string)
		name, _ := values[1].(string)
		if typ != "table" || !strings.EqualFold(name, tableName) {
			return true
		}
		rootPage, _ := toInt(values[3])
		sql, _ := values[4].(string)
		cols, aliasIdx := parseColumnNames(sql)
		found = &tableInfo{rootPage: rootPage, columns: cols, rowidAliasIdx: aliasIdx}
		return false // stop walking, we found it
	})
	if err != nil {
		return tableInfo{}, err
	}
	if found == nil {
		return tableInfo{}, fmt.Errorf("table %q not found", tableName)
	}
	return *found, nil
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

// parseColumnNames extracts column names from a CREATE TABLE statement,
// and identifies the index of an INTEGER PRIMARY KEY column if present
// (SQLite stores that column as a rowid alias - its value is never in the
// record body, see ReadTable). Handles quoted identifiers and nested
// parens (for things like CHECK(...) constraints) well enough for real
// browser-database schemas - not a full SQL grammar parser.
func parseColumnNames(sql string) ([]string, int) {
	open := strings.Index(sql, "(")
	if open == -1 {
		return nil, -1
	}
	depth := 0
	end := -1
	for i := open; i < len(sql); i++ {
		switch sql[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end != -1 {
			break
		}
	}
	if end == -1 {
		return nil, -1
	}
	body := sql[open+1 : end]

	splitTop := func(s string) []string {
		var parts []string
		d := 0
		last := 0
		for i, c := range s {
			switch c {
			case '(':
				d++
			case ')':
				d--
			case ',':
				if d == 0 {
					parts = append(parts, s[last:i])
					last = i + 1
				}
			}
		}
		parts = append(parts, s[last:])
		return parts
	}

	var cols []string
	rowidAliasIdx := -1
	for _, part := range splitTop(body) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		upper := strings.ToUpper(part)
		// Skip table-level constraints, not actual columns.
		if strings.HasPrefix(upper, "PRIMARY KEY") || strings.HasPrefix(upper, "FOREIGN KEY") ||
			strings.HasPrefix(upper, "UNIQUE") || strings.HasPrefix(upper, "CHECK") ||
			strings.HasPrefix(upper, "CONSTRAINT") {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		cols = append(cols, strings.Trim(fields[0], `"'`+"`[]"))
		if strings.Contains(upper, "INTEGER PRIMARY KEY") {
			rowidAliasIdx = len(cols) - 1
		}
	}
	return cols, rowidAliasIdx
}
