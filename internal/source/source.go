package source

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type File struct {
	Path   string
	Source []byte
	AST    *ast.File
}

type Package struct {
	Directory string
	Fset      *token.FileSet
	Files     []*File
}

type Result struct {
	Packages    []*Package
	Diagnostics []error
}

type Provider interface {
	Load() (Result, error)
}

type LocalProvider struct {
	Root string
}

func NewLocalProvider(root string) LocalProvider {
	return LocalProvider{Root: root}
}

func (p LocalProvider) Load() (Result, error) {
	paths, err := discover(p.Root)
	if err != nil {
		return Result{}, err
	}

	groups := make(map[string][]string)
	for _, path := range paths {
		groups[filepath.Dir(path)] = append(groups[filepath.Dir(path)], path)
	}
	dirs := make([]string, 0, len(groups))
	for dir := range groups {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	var result Result
	for _, dir := range dirs {
		fset := token.NewFileSet()
		pkg := &Package{Directory: dir, Fset: fset}
		for _, path := range groups[dir] {
			src, readErr := os.ReadFile(path)
			if readErr != nil {
				return Result{}, fmt.Errorf("read %s: %w", path, readErr)
			}
			file, parseErr := parser.ParseFile(fset, path, src, parser.ParseComments|parser.AllErrors)
			if parseErr != nil {
				result.Diagnostics = append(result.Diagnostics, fmt.Errorf("%s: %w", path, parseErr))
			}
			if file != nil {
				pkg.Files = append(pkg.Files, &File{Path: path, Source: src, AST: file})
			}
		}
		if len(pkg.Files) > 0 {
			result.Packages = append(result.Packages, pkg)
		}
	}
	return result, nil
}

func (p *Package) Position(pos token.Pos) token.Position {
	return p.Fset.Position(pos)
}

func (p *Package) FileForPos(pos token.Pos) *File {
	for _, file := range p.Files {
		if file.AST != nil && pos >= file.AST.Pos() && pos <= file.AST.End() {
			return file
		}
	}
	return nil
}

func (p *Package) SourceExcerpt(pos token.Pos) string {
	file := p.FileForPos(pos)
	if file == nil {
		return ""
	}
	position := p.Fset.Position(pos)
	if position.Line <= 0 {
		return ""
	}
	lines := strings.Split(string(file.Source), "\n")
	if position.Line > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[position.Line-1])
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
