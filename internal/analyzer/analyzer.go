package analyzer

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/rules"
)

type Analyzer struct {
	rules []rules.Rule
}

func New(rs ...rules.Rule) *Analyzer {
	if len(rs) == 0 {
		rs = rules.Default()
	}
	return &Analyzer{rules: rs}
}

func (a *Analyzer) ScanPath(root string) ([]model.Finding, error) {
	paths, err := discover(root)
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	var parseErrors []string
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, src, parser.ParseComments|parser.AllErrors)
		if parseErr != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: %v", path, parseErr))
		}
		if file == nil {
			continue
		}
		ctx := &rules.Context{Path: path, Source: src, Fset: fset, File: file}
		for _, rule := range a.rules {
			findings = append(findings, rule.Analyze(ctx)...)
		}
	}

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

	if len(parseErrors) > 0 {
		return findings, fmt.Errorf("one or more files had parse errors:\n%s", strings.Join(parseErrors, "\n"))
	}
	return findings, nil
}

func discover(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if filepath.Ext(root) != ".gno" {
			return nil, fmt.Errorf("expected a .gno file or directory: %s", root)
		}
		return []string{root}, nil
	}

	var paths []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "bin", "dist":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(path) == ".gno" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}
