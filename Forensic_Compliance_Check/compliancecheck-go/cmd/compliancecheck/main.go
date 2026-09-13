// cmd/compliancecheck/main.go
//
// Single static binary. No install step, no runtime dependency, works
// headless by default (prints/writes JSON) and identically on whatever OS
// it was cross-compiled for. --serve adds an optional point-and-click local
// web UI on top of the exact same scan code the CLI uses - it's a second
// entrypoint to the same engine, not a separate app.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"compliancecheck/internal/model"
	"compliancecheck/internal/report"
	"compliancecheck/internal/scanner"
	"compliancecheck/internal/webui"
)

func main() {
	target := flag.String("target", "", "File or folder to scan (required unless --serve)")
	output := flag.String("output", "", "Write JSON report to this path (default: stdout)")
	minSeverity := flag.String("min-severity", "", "Only include findings at or above this severity: info,low,medium,high,critical")
	flaggedOnly := flag.Bool("flagged-only", false, "Only include flagged findings (excludes clean/info)")
	serve := flag.Bool("serve", false, "Start the local web UI instead of a one-shot scan (binds 127.0.0.1 only)")
	port := flag.Int("port", 8642, "Port for --serve (0 = pick any free port)")
	noBrowser := flag.Bool("no-browser", false, "With --serve, don't try to auto-open a browser (useful on headless machines)")
	flag.Parse()

	if *serve {
		runServe(*port, *noBrowser)
		return
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required (or use --serve for the web UI)")
		flag.Usage()
		os.Exit(2)
	}

	storageScanner, err := scanner.NewStorageScanner()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error initializing scanner:", err)
		os.Exit(1)
	}
	networkScanner := scanner.NewNetworkScanner()
	softwareScanner := scanner.NewSoftwareScanner()
	hardwareScanner := scanner.NewHardwareScanner()
	systemSecurityScanner := scanner.NewSystemSecurityScanner()

	started := time.Now().UTC()
	findings, err := storageScanner.Scan(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error scanning target:", err)
		os.Exit(1)
	}
	findings = append(findings, networkScanner.Scan()...)
	findings = append(findings, softwareScanner.Scan()...)
	findings = append(findings, hardwareScanner.Scan()...)
	findings = append(findings, systemSecurityScanner.Scan()...)
	finished := time.Now().UTC()

	minRank := 0
	if *flaggedOnly {
		minRank = 1
	}
	if *minSeverity != "" {
		minRank = model.Severity(*minSeverity).Rank()
	}
	if minRank > 0 {
		var filtered []model.Finding
		for _, f := range findings {
			if f.Severity.Rank() >= minRank {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	rep := report.Build(findings, started, finished)

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error encoding report:", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error writing report:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *output)
		fmt.Fprintf(os.Stderr, "Findings: %d total, %d flagged\n", rep.Summary.TotalFindings, rep.Summary.FlaggedFindings)
		return
	}
	fmt.Println(string(b))
}

func runServe(port int, noBrowser bool) {
	err := webui.Serve(port, func(addr string) {
		fmt.Fprintf(os.Stderr, "ComplianceCheck web UI running at %s (local machine only)\n", addr)
		fmt.Fprintln(os.Stderr, "Press Ctrl+C to stop.")
		if !noBrowser {
			if openErr := openBrowser(addr); openErr != nil {
				fmt.Fprintf(os.Stderr, "(couldn't auto-open a browser: %v - open the address above manually)\n", openErr)
			}
		}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error starting web UI:", err)
		os.Exit(1)
	}
}

// openBrowser is a best-effort convenience only - failure here is never
// fatal, it just means the person opens the printed URL manually (e.g. on
// a headless server, where this will always "fail" and that's expected).
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
