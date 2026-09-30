package rules

import (
	"go/ast"
	"go/token"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
)

type ExportedPointerLeakRule struct{}

func (ExportedPointerLeakRule) ID() string { return "GNO-STATE-001" }

func (r ExportedPointerLeakRule) Analyze(ctx *Context) []model.Finding {
	pkgPointers := map[string]token.Pos{}
	var findings []model.Finding

	for _, decl := range ctx.File.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			isPointer := isPointerExpr(vs.Type)
			if !isPointer && len(vs.Values) == 1 {
				_, isPointer = vs.Values[0].(*ast.UnaryExpr)
				if unary, ok := vs.Values[0].(*ast.UnaryExpr); ok && unary.Op != token.AND {
					isPointer = false
				}
			}
			if !isPointer {
				continue
			}
			for _, name := range vs.Names {
				pkgPointers[name.Name] = name.Pos()
				if ast.IsExported(name.Name) {
					p := ctx.Fset.Position(name.Pos())
					findings = append(findings, model.Finding{
						RuleID:      r.ID(),
						Title:       "Exported package-level pointer exposes mutable package state",
						Severity:    model.SeverityHigh,
						Confidence:  "high",
						File:        ctx.Path,
						Line:        p.Line,
						Column:      p.Column,
						Evidence:    "exported package-level pointer: " + name.Name,
						Explanation: "Exposing a package-level pointer can publish a live handle to realm state. In Gno, method dispatch and realm storage authority can make pointer exposure security-sensitive even when fields look encapsulated.",
						Remediation: "Keep mutable package state unexported and expose narrowly scoped value/read-only accessors instead of live pointers.",
						References:  []string{"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md"},
					})
				}
			}
		}
	}

	for _, decl := range ctx.File.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil || !ast.IsExported(fn.Name.Name) || !funcReturnsPointer(fn.Type) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, result := range ret.Results {
				id, ok := result.(*ast.Ident)
				if !ok {
					continue
				}
				if _, exists := pkgPointers[id.Name]; !exists {
					continue
				}
				p := ctx.Fset.Position(id.Pos())
				findings = append(findings, model.Finding{
					RuleID:      r.ID(),
					Title:       "Exported getter returns an alias to package-level pointer state",
					Severity:    model.SeverityHigh,
					Confidence:  "high",
					File:        ctx.Path,
					Line:        p.Line,
					Column:      p.Column,
					Evidence:    fn.Name.Name + " returns package-level pointer " + id.Name,
					Explanation: "Returning a live pointer to package/realm state expands the public mutation surface and can interact dangerously with Gno's realm authority and method-dispatch rules.",
					Remediation: "Return a value copy or a narrow read-only result. Do not return aliased pointers to persistent mutable state.",
					References:  []string{"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md"},
				})
			}
			return true
		})
	}

	return findings
}

func isPointerExpr(expr ast.Expr) bool {
	_, ok := expr.(*ast.StarExpr)
	return ok
}

func funcReturnsPointer(ft *ast.FuncType) bool {
	if ft == nil || ft.Results == nil {
		return false
	}
	for _, field := range ft.Results.List {
		if isPointerExpr(field.Type) {
			return true
		}
	}
	return false
}
