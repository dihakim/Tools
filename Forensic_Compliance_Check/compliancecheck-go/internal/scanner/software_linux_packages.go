//go:build linux

// internal/scanner/software_linux_packages.go
//
// Installed-software inventory. Debian/Ubuntu: parsed directly from
// /var/lib/dpkg/status (pure stdlib, no exec - dpkg's status file is
// plain text and stable). RedHat/Fedora/SUSE: no equivalent readable
// flat file (rpm's database is a binary format), so this falls back to
// invoking `rpm` IF it's already present on the system - that's using an
// existing system tool, not installing anything new, same principle as
// invoking the OS's own browser-opener for --serve.
//
// Individual packages aren't inherently suspicious, so (unlike the file
// scanner) this doesn't emit one Finding per package - a base Debian
// install alone is 500-2000+ packages, and nobody manually reviews that
// list item by item. Instead: one summary Finding carries the full
// inventory in its evidence for anyone who does want to grep/search it,
// and separate Findings are only raised for packages in a broken/partial
// install state, which IS worth a human's attention.
package scanner

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"compliancecheck/internal/model"
)

type pkgInfo struct {
	name    string
	version string
	arch    string
	section string
	status  string // full status line, e.g. "install ok installed"
}

func scanSoftwarePackages() []model.Finding {
	var out []model.Finding
	var pkgs []pkgInfo
	var source string

	if p, err := parseDpkgStatus("/var/lib/dpkg/status"); err == nil {
		pkgs = p
		source = "dpkg (/var/lib/dpkg/status)"
	} else if p, err := parseRPMIfAvailable(); err == nil && len(p) > 0 {
		pkgs = p
		source = "rpm -qa"
	} else {
		f := model.NewFinding(model.CategorySoftware, "packages_unavailable", "Could not determine installed packages", model.SeverityInfo)
		f.Source = "software.packages"
		f.Detail = "No readable dpkg status file and no rpm binary found on PATH."
		return []model.Finding{f}
	}

	brokenCount := 0
	for _, p := range pkgs {
		if p.status != "" && !strings.HasSuffix(p.status, " installed") {
			brokenCount++
			f := model.NewFinding(model.CategorySoftware, "package_broken_state", "Package in a broken/partial install state", model.SeverityLow)
			f.Source = "software.packages"
			f.Location = p.name
			f.Detail = p.name + " " + p.version + " - status: " + p.status
			f.Evidence["version"] = p.version
			f.Evidence["architecture"] = p.arch
			f.Evidence["status"] = p.status
			out = append(out, f)
		}
	}

	summary := model.NewFinding(model.CategorySoftware, "installed_packages_summary", "Installed software inventory", model.SeverityClean)
	summary.Source = "software.packages"
	summary.Detail = strconv.Itoa(len(pkgs)) + " packages installed (source: " + source + "), " + strconv.Itoa(brokenCount) + " in a broken/partial state"
	summary.Evidence["source"] = source
	summary.Evidence["total_count"] = len(pkgs)
	summary.Evidence["broken_count"] = brokenCount
	summary.Evidence["packages"] = packageList(pkgs)
	out = append(out, summary)

	return out
}

func packageList(pkgs []pkgInfo) []string {
	list := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		list = append(list, p.name+"="+p.version)
	}
	return list
}

func parseDpkgStatus(path string) ([]pkgInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []pkgInfo
	var cur pkgInfo
	flush := func() {
		if cur.name != "" {
			pkgs = append(pkgs, cur)
		}
		cur = pkgInfo{}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // some Description fields run long
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package:"):
			cur.name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Status:"):
			cur.status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		case strings.HasPrefix(line, "Version:"):
			cur.version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Architecture:"):
			cur.arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		case strings.HasPrefix(line, "Section:"):
			cur.section = strings.TrimSpace(strings.TrimPrefix(line, "Section:"))
		}
	}
	flush()
	return pkgs, scanner.Err()
}

func parseRPMIfAvailable() ([]pkgInfo, error) {
	rpmPath, err := exec.LookPath("rpm")
	if err != nil {
		return nil, err
	}
	out, err := exec.Command(rpmPath, "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []pkgInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			continue
		}
		pkgs = append(pkgs, pkgInfo{name: fields[0], version: fields[1], arch: fields[2], status: "install ok installed"})
	}
	return pkgs, nil
}
