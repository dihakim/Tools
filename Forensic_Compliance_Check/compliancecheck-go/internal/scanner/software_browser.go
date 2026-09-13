// internal/scanner/software_browser.go
//
// Browser history and bookmarks forensics. Reads Firefox's places.sqlite
// (moz_places, moz_bookmarks) and Chrome/Edge/Brave's History file (urls
// table) via internal/sqlitemin - the pure-Go SQLite reader built and
// verified specifically for this feature.
//
// Deliberately scoped to history/bookmarks only - this does NOT read or
// decrypt saved login credentials (Chrome's "Login Data" file, Firefox's
// key4.db/logins.json). That specific capability - generically decrypting
// every saved browser password in one pass - is also the signature core
// feature of commodity credential-stealing malware (RedLine, Vidar,
// LummaC2, and similar infostealers all implement exactly this). History
// and bookmarks are just reading local unencrypted metadata, the same
// sensitivity as every other file this tool reads; a generic saved-
// password decryptor is a different kind of artifact regardless of the
// stated purpose behind building it, and isn't included here.
//
// Rather than emit one Finding per URL (which would flood the report with
// potentially thousands of entries and is disproportionate for what's
// fundamentally a browsing-history summary, not per-item suspicious
// content), this emits one summary Finding per browser profile with
// aggregate stats plus a capped sample in evidence, matching the pattern
// already used for installed-software inventory. Domains are cross-
// checked against the small bundled website-reputation reference data
// (internal/hwintel) - a real, if small-sample, way to surface "visited a
// known-bad domain" without needing a live threat-intel connection.
//
// Databases are read directly from disk without copying, which means a
// currently-running browser holding a write lock (WAL mode) may cause a
// read to fail or return slightly stale data - standard forensic practice
// is to work from a copy of a live system's files, and this doesn't
// attempt to work around that.
package scanner

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"compliancecheck/internal/hwintel"
	"compliancecheck/internal/model"
	"compliancecheck/internal/sqlitemin"
)

const maxHistoryRows = 2000  // per-profile cap, keeps memory/time bounded on huge histories
const maxSampleInEvidence = 25

func scanBrowsers() []model.Finding {
	var out []model.Finding
	out = append(out, scanFirefoxProfiles()...)
	out = append(out, scanChromiumProfiles("Google Chrome", chromeProfileDirs())...)
	out = append(out, scanChromiumProfiles("Microsoft Edge", edgeProfileDirs())...)
	if len(out) == 0 {
		f := model.NewFinding(model.CategorySoftware, "browser_none_found", "No supported browser profiles found", model.SeverityInfo)
		f.Source = "software.browser"
		out = append(out, f)
	}
	return out
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// --- Firefox ---

func firefoxProfilesRoot() string {
	home := homeDir()
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	default:
		return filepath.Join(home, ".mozilla", "firefox")
	}
}

func scanFirefoxProfiles() []model.Finding {
	root := firefoxProfilesRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		f := model.NewFinding(model.CategorySoftware, "browser_firefox_unavailable", "Firefox profiles", model.SeverityInfo)
		f.Source = "software.browser"
		f.Detail = "No Firefox profile directory found at " + root + " (" + err.Error() + ")."
		return []model.Finding{f}
	}

	var out []model.Finding
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		placesPath := filepath.Join(root, e.Name(), "places.sqlite")
		if _, err := os.Stat(placesPath); err != nil {
			continue
		}
		out = append(out, summarizeFirefoxHistory(placesPath)...)
	}
	return out
}

func summarizeFirefoxHistory(placesPath string) []model.Finding {
	db, err := sqlitemin.Open(placesPath)
	if err != nil {
		f := model.NewFinding(model.CategorySoftware, "browser_firefox_unreadable", "Could not read Firefox history", model.SeverityInfo)
		f.Source = "software.browser"
		f.Location = placesPath
		f.Detail = err.Error() + " (a running Firefox instance can hold a lock on this file - close it and retry for a reliable read)."
		return []model.Finding{f}
	}
	defer db.Close()

	var out []model.Finding

	places, err := db.ReadTable("moz_places", maxHistoryRows)
	if err == nil && len(places) > 0 {
		out = append(out, buildHistorySummary("Firefox", placesPath, places, "url", "title", "visit_count")...)
	}

	bookmarks, err := db.ReadTable("moz_bookmarks", maxHistoryRows)
	if err == nil {
		placeByID := map[int64]map[string]any{}
		for _, p := range places {
			if id, ok := p["id"].(int64); ok {
				placeByID[id] = p
			}
		}
		var titles []string
		for _, b := range bookmarks {
			title, _ := b["title"].(string)
			fk, _ := b["fk"].(int64)
			if title == "" {
				continue
			}
			if p, ok := placeByID[fk]; ok {
				if u, ok := p["url"].(string); ok {
					titles = append(titles, title+" -> "+u)
					continue
				}
			}
			titles = append(titles, title)
		}
		if len(titles) > 0 {
			f := model.NewFinding(model.CategorySoftware, "browser_bookmarks", "Firefox bookmarks", model.SeverityClean)
			f.Source = "software.browser"
			f.Location = placesPath
			f.Detail = fmt.Sprintf("%d bookmarks found.", len(titles))
			f.Evidence["count"] = len(titles)
			f.Evidence["sample"] = capSlice(titles, maxSampleInEvidence)
			out = append(out, f)
		}
	}

	return out
}

// --- Chromium-family (Chrome, Edge) ---

func chromeProfileDirs() []string { return chromiumRoots("google-chrome", "Google", "Chrome") }
func edgeProfileDirs() []string   { return chromiumRoots("microsoft-edge", "Microsoft", "Edge") }

// chromiumRoots returns the base "User Data"-equivalent directory for a
// Chromium-family browser across OSes. linuxDir is the ~/.config/<name>
// directory name; macSubdirs/windows names follow each browser's actual
// vendor/product folder naming.
func chromiumRoots(linuxDir, vendor, product string) []string {
	home := homeDir()
	var base string
	switch runtime.GOOS {
	case "windows":
		base = filepath.Join(os.Getenv("LOCALAPPDATA"), vendor, product, "User Data")
	case "darwin":
		base = filepath.Join(home, "Library", "Application Support", vendor, product)
	default:
		base = filepath.Join(home, ".config", linuxDir)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var profiles []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "Default" || strings.HasPrefix(e.Name(), "Profile ") {
			profiles = append(profiles, filepath.Join(base, e.Name()))
		}
	}
	return profiles
}

func scanChromiumProfiles(browserName string, profileDirs []string) []model.Finding {
	if profileDirs == nil {
		f := model.NewFinding(model.CategorySoftware, "browser_"+sanitizeSubtype(browserName)+"_unavailable", browserName+" profiles", model.SeverityInfo)
		f.Source = "software.browser"
		f.Detail = "No " + browserName + " profile directory found on this system."
		return []model.Finding{f}
	}

	var out []model.Finding
	for _, dir := range profileDirs {
		historyPath := filepath.Join(dir, "History")
		if _, err := os.Stat(historyPath); err != nil {
			continue
		}
		out = append(out, summarizeChromiumHistory(browserName, historyPath)...)
	}
	return out
}

func summarizeChromiumHistory(browserName, historyPath string) []model.Finding {
	db, err := sqlitemin.Open(historyPath)
	if err != nil {
		f := model.NewFinding(model.CategorySoftware, "browser_"+sanitizeSubtype(browserName)+"_unreadable", "Could not read "+browserName+" history", model.SeverityInfo)
		f.Source = "software.browser"
		f.Location = historyPath
		f.Detail = err.Error() + " (a running browser instance can hold a lock on this file - close it and retry for a reliable read)."
		return []model.Finding{f}
	}
	defer db.Close()

	urls, err := db.ReadTable("urls", maxHistoryRows)
	if err != nil || len(urls) == 0 {
		return nil
	}
	return buildHistorySummary(browserName, historyPath, urls, "url", "title", "visit_count")
}

// --- shared summary building + domain reputation cross-check ---

func buildHistorySummary(browserName, path string, rows []map[string]any, urlKey, titleKey, visitKey string) []model.Finding {
	var out []model.Finding

	domainCounts := map[string]int{}
	var sample []string
	for i, r := range rows {
		u, _ := r[urlKey].(string)
		if u == "" {
			continue
		}
		if i < maxSampleInEvidence {
			title, _ := r[titleKey].(string)
			sample = append(sample, title+" | "+u)
		}
		if d := extractDomain(u); d != "" {
			domainCounts[d]++
		}
	}

	summary := model.NewFinding(model.CategorySoftware, "browser_history", browserName+" browsing history", model.SeverityClean)
	summary.Source = "software.browser"
	summary.Location = path
	summary.Detail = fmt.Sprintf("%d history entries across %d distinct domains.", len(rows), len(domainCounts))
	summary.Evidence["entry_count"] = len(rows)
	summary.Evidence["distinct_domains"] = len(domainCounts)
	summary.Evidence["top_domains"] = topDomains(domainCounts, 15)
	summary.Evidence["sample"] = sample
	out = append(out, summary)

	// Cross-check every distinct visited domain against the bundled
	// reputation reference data - small sample dataset, but a hit is
	// meaningful signal, matching the pattern used elsewhere for
	// blacklist/CVE cross-referencing.
	for domain := range domainCounts {
		if rep, ok := hwintel.LookupWebsiteReputation(domain); ok && rep.IsMalicious == 1 {
			f := model.NewFinding(model.CategorySoftware, "browser_visited_known_bad_domain", browserName+" history contains a known-bad domain", model.SeverityHigh)
			f.Source = "software.browser"
			f.Location = path
			f.Detail = fmt.Sprintf("Visited %s, %d time(s) - flagged %s risk in the bundled domain reputation reference data (category: %s).", domain, domainCounts[domain], rep.RiskLevel, rep.Category)
			f.Evidence["domain"] = domain
			f.Evidence["visit_count"] = domainCounts[domain]
			f.Evidence["risk_level"] = rep.RiskLevel
			f.Evidence["reputation_score"] = rep.ReputationScore
			out = append(out, f)
		}
	}

	return out
}

func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func topDomains(counts map[string]int, n int) []map[string]any {
	type kv struct {
		domain string
		count  int
	}
	var list []kv
	for d, c := range counts {
		list = append(list, kv{d, c})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].count > list[j].count })
	if len(list) > n {
		list = list[:n]
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, map[string]any{"domain": e.domain, "visits": e.count})
	}
	return out
}

func capSlice(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func sanitizeSubtype(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
