// internal/report/report.go
package report

import (
	"runtime"
	"time"

	"compliancecheck/internal/model"
)

type Report struct {
	Host              HostInfo                          `json:"host"`
	StartedAt         time.Time                          `json:"started_at"`
	FinishedAt        time.Time                          `json:"finished_at"`
	Summary           Summary                            `json:"summary"`
	FindingsByCategory map[model.Category][]model.Finding `json:"findings_by_category"`
	Findings          []model.Finding                    `json:"findings"`
}

type HostInfo struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Summary struct {
	TotalFindings   int                    `json:"total_findings"`
	FlaggedFindings int                    `json:"flagged_findings"`
	BySeverity      map[model.Severity]int `json:"by_severity"`
}

func Build(findings []model.Finding, startedAt, finishedAt time.Time) Report {
	byCat := map[model.Category][]model.Finding{
		model.CategorySoftware: {},
		model.CategoryHardware: {},
		model.CategoryStorage:  {},
		model.CategoryNetwork:  {},
		model.CategoryUsers:    {},
	}
	bySev := map[model.Severity]int{
		model.SeverityClean: 0, model.SeverityInfo: 0, model.SeverityLow: 0,
		model.SeverityMedium: 0, model.SeverityHigh: 0, model.SeverityCritical: 0,
	}
	flagged := 0
	for _, f := range findings {
		byCat[f.Category] = append(byCat[f.Category], f)
		bySev[f.Severity]++
		if f.Severity.IsFlagged() {
			flagged++
		}
	}

	return Report{
		Host:               HostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH},
		StartedAt:          startedAt,
		FinishedAt:         finishedAt,
		FindingsByCategory: byCat,
		Findings:           findings,
		Summary: Summary{
			TotalFindings:   len(findings),
			FlaggedFindings: flagged,
			BySeverity:      bySev,
		},
	}
}
