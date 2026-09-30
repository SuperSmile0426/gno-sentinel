package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/rules"
	"github.com/SuperSmile0426/gno-sentinel/internal/source"
)

type Options struct {
	Metadata model.AnalysisMetadata
}

type Analyzer struct {
	rules    []rules.Rule
	metadata model.AnalysisMetadata
}

func New(rs ...rules.Rule) *Analyzer {
	return NewWithOptions(Options{}, rs...)
}

func NewWithOptions(opts Options, rs ...rules.Rule) *Analyzer {
	if len(rs) == 0 {
		rs = rules.Default()
	}
	return &Analyzer{rules: rs, metadata: opts.Metadata}
}

func (a *Analyzer) ScanPath(root string) ([]model.Finding, error) {
	return a.ScanProvider(source.NewLocalProvider(root))
}

func (a *Analyzer) ScanProvider(provider source.Provider) ([]model.Finding, error) {
	result, err := provider.Load()
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	for _, pkg := range result.Packages {
		ctx := &rules.Context{Package: pkg, Metadata: a.metadata}
		for _, rule := range a.rules {
			findings = append(findings, rule.Analyze(ctx)...)
		}
	}

	sortFindings(findings)
	if len(result.Diagnostics) > 0 {
		parts := make([]string, 0, len(result.Diagnostics))
		for _, diagnostic := range result.Diagnostics {
			parts = append(parts, diagnostic.Error())
		}
		return findings, fmt.Errorf("one or more files had parse errors:\n%s", strings.Join(parts, "\n"))
	}
	return findings, nil
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Column != findings[j].Column {
			return findings[i].Column < findings[j].Column
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}
