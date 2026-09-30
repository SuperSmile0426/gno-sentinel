package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/SuperSmile0426/gno-sentinel/internal/analyzer"
	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/report"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
		return 0
	}
	if args[0] != "scan" {
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "none", "exit 2 when findings are at or above: high, medium, low, info, none")
	gnoVersion := fs.String("gno-version", "", "optional Gno version/build metadata attached to findings")
	network := fs.String("network", "", "optional network metadata attached to findings")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan requires exactly one .gno file or directory")
		return 2
	}

	a := analyzer.NewWithOptions(analyzer.Options{Metadata: model.AnalysisMetadata{
		GnoVersion: *gnoVersion,
		Network:    *network,
	}})
	findings, err := a.ScanPath(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}

	switch strings.ToLower(*format) {
	case "text":
		if e := report.Text(os.Stdout, findings); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
	case "json":
		if e := report.JSON(os.Stdout, findings); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported format %q\n", *format)
		return 2
	}

	threshold, ok := parseThreshold(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "unsupported --fail-on value %q\n", *failOn)
		return 2
	}
	if threshold > 0 && reachesThreshold(findings, threshold) {
		return 2
	}
	if err != nil {
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "gno-sentinel scan [--format text|json] [--fail-on high|medium|low|info|none] [--gno-version version] [--network name] <path>")
}

func parseThreshold(v string) (int, bool) {
	switch strings.ToLower(v) {
	case "none":
		return 0, true
	case "high":
		return 4, true
	case "medium":
		return 3, true
	case "low":
		return 2, true
	case "info":
		return 1, true
	default:
		return 0, false
	}
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func reachesThreshold(findings []model.Finding, threshold int) bool {
	for _, f := range findings {
		if severityRank(f.Severity) >= threshold {
			return true
		}
	}
	return false
}
