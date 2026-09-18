// internal/webui/server.go
//
// Local-only web UI. Binds to 127.0.0.1, never 0.0.0.0 - this is a
// point-and-click convenience layer over the same ComplianceRunner-style
// scan the CLI uses, not a network service. Nothing here makes any
// outbound request; the single HTML asset is embedded into the binary via
// go:embed, so there's no CDN, no external script, no phone-home of any
// kind, on a machine with zero internet access this works identically.
package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"compliancecheck/internal/cipher"
	"compliancecheck/internal/forensics"
	"compliancecheck/internal/langdata"
	"compliancecheck/internal/langdetect"
	"compliancecheck/internal/model"
	"compliancecheck/internal/pii"
	"compliancecheck/internal/report"
	"compliancecheck/internal/scanner"
	"compliancecheck/internal/translate"
)

//go:embed assets/index.html
var assets embed.FS

// Shared, cheap-to-construct singletons for the on-demand tool endpoints
// (cipher/PII), loaded once rather than per-request.
var sharedLangDetect *langdetect.Detector
var sharedPII *pii.Detector

func init() {
	sharedLangDetect, _ = langdetect.Load()
	sharedPII, _ = pii.Load()
}

type scanRequest struct {
	Target     string              `json:"target"`     // back-compat: single path
	Targets    []string            `json:"targets"`     // preferred: one or more paths (files and/or folders mixed)
	Categories []string            `json:"categories"`
	Checks     map[string][]string `json:"checks"`      // category -> selected check IDs; omitted/empty category = everything
	PIITypes   []string            `json:"pii_types"`   // PII rule IDs to search for; empty = all
	CustomNames []pii.NameQuery    `json:"custom_names"` // find these specific people (any format variant)
	CustomTerms []pii.TermQuery    `json:"custom_terms"` // find these exact strings/regexes
}

type browseRequest struct {
	Mode string `json:"mode"` // "folder" | "files"
}

// Serve starts the local web UI on 127.0.0.1:port (0 = pick any free port)
// and blocks until the server stops. Returns the actual address bound, so
// the caller can print/open it, before blocking.
func Serve(port int, onReady func(addr string)) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := assets.ReadFile("assets/index.html")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		targets := req.Targets
		if len(targets) == 0 && req.Target != "" {
			targets = []string{req.Target}
		}
		wantsFiles := len(req.Categories) == 0
		for _, c := range req.Categories {
			if c == "files" {
				wantsFiles = true
				break
			}
		}
		if wantsFiles && len(targets) == 0 {
			http.Error(w, "target is required", http.StatusBadRequest)
			return
		}
		req.Targets = targets

		rep, err := runScan(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rep)
	})

	mux.HandleFunc("/api/browse", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req browseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Mode != "files" && req.Mode != "folder" {
			req.Mode = "folder"
		}
		paths, err := browseNative(req.Mode)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"paths": paths})
	})

	mux.HandleFunc("/api/checks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string][]CheckDefinition{}
		for cat, defs := range allChecksByCategory {
			out[cat] = defs
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/pii/types", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if sharedPII == nil {
			json.NewEncoder(w).Encode(map[string]any{"error": "PII rules failed to load"})
			return
		}
		json.NewEncoder(w).Encode(sharedPII.ListRules())
	})

	mux.HandleFunc("/api/cipher/analyze", jsonPostHandler(func(req struct {
		Text string
		Lang string // optional dictionary-gloss language hint ("" = auto)
	}) any {
		res := cipher.Analyze(req.Text, sharedLangDetect)
		mergeTranslation(&res, req.Text, req.Lang)
		return res
	}))

	mux.HandleFunc("/api/cipher/decode", jsonPostHandler(func(req struct {
		Method  string
		Text    string
		Key     string
		Variant string
	}) any {
		return cipher.Decode(req.Method, req.Text, req.Key, req.Variant, sharedLangDetect)
	}))

	mux.HandleFunc("/api/cipher/encode", jsonPostHandler(func(req struct {
		Method  string
		Text    string
		Key     string
		Variant string
	}) any {
		return cipher.Encode(req.Method, req.Text, req.Key, req.Variant)
	}))

	mux.HandleFunc("/api/cipher/variants", jsonPostHandler(func(req struct{ Method string }) any {
		return map[string]any{"method": req.Method, "variants": cipher.VariantsFor(req.Method)}
	}))

	mux.HandleFunc("/api/tools/hash", jsonPostHandler(func(req struct{ Path string }) any {
		h, err := forensics.HashFile(req.Path)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return h
	}))

	mux.HandleFunc("/api/tools/identify-hash", jsonPostHandler(func(req struct{ Hash string }) any {
		return map[string]any{"hash": req.Hash, "likely_algorithms": forensics.IdentifyHash(req.Hash)}
	}))

	mux.HandleFunc("/api/tools/jwt-decode", jsonPostHandler(func(req struct{ Token string }) any {
		return forensics.DecodeJWT(req.Token)
	}))

	mux.HandleFunc("/api/translate/languages", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var out []map[string]string
		for _, code := range langdata.Codes() {
			lang, _ := langdata.Get(code)
			if lang.HasDictionary() {
				out = append(out, map[string]string{"code": code, "name": lang.Name})
			}
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/translate", jsonPostHandler(func(req struct {
		Text string
		Lang string
	}) any {
		result, ok := translate.Translate(req.Text, req.Lang)
		if !ok {
			return map[string]any{"error": "no dictionary data available for language: " + req.Lang}
		}
		return result
	}))

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	addr := "http://" + ln.Addr().String()
	if onReady != nil {
		onReady(addr)
	}

	srv := &http.Server{Handler: mux}
	log.SetOutput(logDiscard{}) // keep stdout clean for scripting; server errors still returned to caller
	return srv.Serve(ln)
}

// mergeTranslation fills res.Translation with a rough dictionary gloss of
// the input, merging the standalone Translate tool into the Analyze & Decode
// flow: an explicit language hint always glosses; otherwise a recognized
// input language glosses in that language; otherwise (input not recognized,
// no classical crack found) we auto-pick the dictionary language with the
// best coverage - the "this might be an unsupported language" fallback that
// turns the old dead-end message into an actual dictionary rendering.
func mergeTranslation(res *cipher.AnalyzeResult, text, lang string) {
	if lang != "" {
		if t, ok := translate.Translate(text, lang); ok {
			res.Translation = &t
		}
		return
	}
	if res.InputLanguage != nil {
		if t, ok := translate.Translate(text, res.InputLanguage.Language); ok {
			res.Translation = &t
		}
		return
	}
	if res.ClassicalCrack == nil {
		if t, ok := translate.TranslateAuto(text); ok {
			res.Translation = &t
		}
	}
}

type logDiscard struct{}

func (logDiscard) Write(p []byte) (int, error) { return len(p), nil }

// jsonPostHandler is a small generic helper: decode a JSON POST body into T,
// call fn, encode whatever it returns as the JSON response. Used for the
// stateless on-demand tool endpoints (cipher/hash/JWT) so each one is just
// a one-line route registration instead of repeating decode/encode
// boilerplate five times.
func jsonPostHandler[T any](fn func(T) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req T
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fn(req))
	}
}

func runScan(req scanRequest) (map[string]any, error) {
	wanted := map[string]bool{}
	for _, c := range req.Categories {
		wanted[c] = true
	}
	if len(wanted) == 0 {
		wanted = map[string]bool{"files": true, "network": true, "software": true, "hardware": true}
	}

	started := time.Now().UTC()
	var findings []model.Finding

	if wanted["files"] {
		storageScanner, err := scanner.NewStorageScanner()
		if err != nil {
			return nil, err
		}
		if len(req.PIITypes) > 0 {
			storageScanner.PIIFilter = map[string]bool{}
			for _, id := range req.PIITypes {
				storageScanner.PIIFilter[id] = true
			}
		}
		if len(req.CustomNames) > 0 || len(req.CustomTerms) > 0 {
			storageScanner.CustomNames = req.CustomNames
			storageScanner.CustomTerms = req.CustomTerms
			if errs := storageScanner.PrepareCustomSearches(); len(errs) > 0 {
				msgs := make([]string, len(errs))
				for i, e := range errs {
					msgs[i] = e.Error()
				}
				return nil, fmt.Errorf("custom search error(s): %s", strings.Join(msgs, "; "))
			}
		}
		for _, target := range req.Targets {
			f, err := storageScanner.Scan(target)
			if err != nil {
				return nil, err
			}
			findings = append(findings, f...)
		}
		// SSH/SUID/credential-file checks scan fixed system locations, not
		// the user's --target, but conceptually belong with "files" in the UI.
		findings = append(findings, scanner.NewSystemSecurityScanner().Scan()...)
	}
	if wanted["network"] {
		findings = append(findings, scanner.NewNetworkScanner().Scan()...)
	}
	if wanted["software"] {
		findings = append(findings, scanner.NewSoftwareScanner().Scan()...)
	}
	if wanted["hardware"] {
		findings = append(findings, scanner.NewHardwareScanner().Scan()...)
	}

	findings = applyCheckFilters(findings, req.Checks)

	finished := time.Now().UTC()
	rep := report.Build(findings, started, finished)

	b, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// requestCategoryToModel maps the CLI/API's category keys ("files") to the
// model.Category the resulting findings actually carry ("storage").
var requestCategoryToModel = map[string]model.Category{
	"files":    model.CategoryStorage,
	"network":  model.CategoryNetwork,
	"software": model.CategorySoftware,
	"hardware": model.CategoryHardware,
}

func applyCheckFilters(findings []model.Finding, checks map[string][]string) []model.Finding {
	if len(checks) == 0 {
		return findings
	}
	// Precompute allowed-prefix lists per model category, only for categories
	// where a selection was actually made.
	prefixesByCategory := map[model.Category][]string{}
	for reqCat, selected := range checks {
		modelCat, ok := requestCategoryToModel[reqCat]
		if !ok {
			continue
		}
		if prefixes, active := resolvePrefixes(reqCat, selected); active {
			prefixesByCategory[modelCat] = prefixes
		}
	}
	if len(prefixesByCategory) == 0 {
		return findings
	}

	var out []model.Finding
	for _, f := range findings {
		prefixes, filtered := prefixesByCategory[f.Category]
		if !filtered || subtypeAllowed(f.Subtype, prefixes) {
			out = append(out, f)
		}
	}
	return out
}
