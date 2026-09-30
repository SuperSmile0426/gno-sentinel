package rules

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/source"
)

type Context struct {
	Package  *source.Package
	Metadata model.AnalysisMetadata
}

type Rule interface {
	ID() string
	Analyze(*Context) []model.Finding
}

func Default() []Rule {
	return []Rule{
		PaymentUserCallRule{},
		OriginCallerAuthRule{},
		ExportedPointerLeakRule{},
		UnsafePreviousRealmRule{},
	}
}

func callSelectorName(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	return sel.Sel.Name, true
}

func selectorCall(call *ast.CallExpr) (receiver, name string, ok bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", sel.Sel.Name, false
	}
	return id.Name, sel.Sel.Name, true
}

func containsCallSelector(expr ast.Expr, name string) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := callSelectorName(call); ok && selector == name {
			found = call
			return false
		}
		return true
	})
	return found
}

func importAliases(file *ast.File, importPaths ...string) map[string]bool {
	wanted := make(map[string]bool, len(importPaths))
	for _, path := range importPaths {
		wanted[path] = true
	}
	aliases := map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !wanted[path] {
			continue
		}
		name := defaultImportName(path)
		if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
			name = imp.Name.Name
		}
		aliases[name] = true
	}
	return aliases
}

func defaultImportName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

func findingAt(ctx *Context, file *source.File, pos token.Pos, finding model.Finding) model.Finding {
	p := ctx.Package.Position(pos)
	finding.File = file.Path
	finding.Line = p.Line
	finding.Column = p.Column
	finding.SourceExcerpt = ctx.Package.SourceExcerpt(pos)
	finding.GnoVersion = ctx.Metadata.GnoVersion
	finding.Network = ctx.Metadata.Network
	return finding
}
