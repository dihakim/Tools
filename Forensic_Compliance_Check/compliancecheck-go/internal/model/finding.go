// internal/model/finding.go
//
// Unified data model, same shape as the Python core/finding.py it replaces.
// Every scanner (storage, network, software, hardware, users) emits Findings
// in this format. Clean results are Findings too (Severity = Clean) so the
// manual-review report always contains everything that was checked, not
// just what got flagged.
package model

import "time"

type Category string

const (
	CategorySoftware Category = "software"
	CategoryHardware Category = "hardware"
	CategoryStorage  Category = "storage"
	CategoryNetwork  Category = "network"
	CategoryUsers    Category = "users"
)

type Severity string

const (
	SeverityClean    Severity = "clean"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank gives a numeric ordering so callers can filter/sort ("--min-severity medium").
func (s Severity) Rank() int {
	switch s {
	case SeverityClean, SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

func (s Severity) IsFlagged() bool {
	return s.Rank() > 0
}

type Finding struct {
	Category  Category               `json:"category"`
	Subtype   string                 `json:"subtype"`
	Title     string                 `json:"title"`
	Severity  Severity               `json:"severity"`
	Detail    string                 `json:"detail,omitempty"`
	Source    string                 `json:"source,omitempty"`
	Location  string                 `json:"location,omitempty"`
	Language  string                 `json:"language,omitempty"` // ISO 639-1, when the finding is text-content-derived
	Evidence  map[string]any         `json:"evidence,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
	ScannedAt time.Time              `json:"scanned_at"`
}

func NewFinding(cat Category, subtype, title string, sev Severity) Finding {
	return Finding{
		Category:  cat,
		Subtype:   subtype,
		Title:     title,
		Severity:  sev,
		ScannedAt: time.Now().UTC(),
		Evidence:  map[string]any{},
	}
}
