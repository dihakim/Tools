//go:build linux

// internal/scanner/hardware_linux_cpumem.go
package scanner

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"compliancecheck/internal/model"
)

func scanCPU() []model.Finding {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return []model.Finding{unreadableHW("cpu", err)}
	}
	defer f.Close()

	model_ := ""
	cores := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") && model_ == "" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				model_ = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}

	finding := model.NewFinding(model.CategoryHardware, "cpu", "CPU", model.SeverityInfo)
	finding.Source = "hardware.cpu"
	finding.Detail = model_
	finding.Evidence["model"] = model_
	finding.Evidence["logical_cores"] = cores
	return []model.Finding{finding}
}

func scanMemory() []model.Finding {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return []model.Finding{unreadableHW("memory", err)}
	}
	defer f.Close()

	values := map[string]int64{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.Fields(strings.TrimSpace(parts[1]))
		if len(valStr) == 0 {
			continue
		}
		if v, err := strconv.ParseInt(valStr[0], 10, 64); err == nil {
			values[key] = v // kB
		}
	}

	totalKB := values["MemTotal"]
	availKB := values["MemAvailable"]

	finding := model.NewFinding(model.CategoryHardware, "memory", "System memory", model.SeverityInfo)
	finding.Source = "hardware.memory"
	finding.Detail = kbToGBString(totalKB) + " total, " + kbToGBString(availKB) + " available"
	finding.Evidence["total_kb"] = totalKB
	finding.Evidence["available_kb"] = availKB
	return []model.Finding{finding}
}

func kbToGBString(kb int64) string {
	gb := float64(kb) / (1024 * 1024)
	return strconv.FormatFloat(gb, 'f', 1, 64) + " GB"
}

func unreadableHW(what string, err error) model.Finding {
	f := model.NewFinding(model.CategoryHardware, what+"_unreadable", "Could not read "+what+" info", model.SeverityInfo)
	f.Source = "hardware." + what
	f.Detail = err.Error()
	return f
}
