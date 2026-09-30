package rules

import (
	"go/ast"
	"go/token"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/source"
)

type ExportedPointerLeakRule struct{}

func (ExportedPointerLeakRule) ID() string { return "GNO-STATE-001" }

type packagePointer struct {
	file *source.File
	pos  token.Pos
}

func (r ExportedPointerLeakRule) Analyze(ctx *Context) []model.Finding {
	pkgPointers := map[string]packagePointer{}
	var findings []model.Finding

	for _, file := range ctx.Package.Files {
		for _, decl := range file.AST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || !valueSpecIsPointer(vs) {
					continue
				}
				for _, name := range vs.Names {
					pkgPointers[name.Name] = packagePointer{file: file, pos: name.Pos()}
					if ast.IsExported(name.Name) {
						findings = append(findings, findingAt(ctx, file, name.Pos(), model.Finding{
							RuleID:        r.ID(),
							Title:         "Exported package-level pointer exposes mutable package state",
							Severity:      model.SeverityHigh,
							Confidence:    "high",
							Evidence:      "exported package-level pointer: " + name.Name,
							Explanation:   "Exposing a package-level pointer can publish a live handle to realm state. In Gno, method dispatch and realm storage authority can make pointer exposure security-sensitive even when fields look encapsulated.",
							Remediation:   "Keep mutable package state unexported and expose narrowly scoped value/read-only accessors instead of live pointers.",
							References:    []string{"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md"},
							Applicability: "Current documented pointer/capability safety guidance; exact historical version boundaries not yet encoded.",
						}))
					}
				}
			}
		}
	}

	for _, file := range ctx.Package.Files {
		for _, decl := range file.AST.Decls {
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
					findings = append(findings, findingAt(ctx, file, id.Pos(), model.Finding{
						RuleID:        r.ID(),
						Title:         "Exported getter returns an alias to package-level pointer state",
						Severity:      model.SeverityHigh,
						Confidence:    "high",
						Evidence:      fn.Name.Name + " returns package-level pointer " + id.Name,
						Explanation:   "Returning a live pointer to package/realm state expands the public mutation surface and can interact dangerously with Gno's realm authority and method-dispatch rules. Package-level analysis is required because the state declaration and getter may live in different .gno files.",
						Remediation:   "Return a value copy or a narrow read-only result. Do not return aliased pointers to persistent mutable state.",
						References:    []string{"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md"},
						Applicability: "Current documented pointer/capability safety guidance; exact historical version boundaries not yet encoded.",
					}))
				}
				return true
			})
		}
	}

	return findings
}

func valueSpecIsPointer(vs *ast.ValueSpec) bool {
	if isPointerExpr(vs.Type) {
		return true
	}
	for _, value := range vs.Values {
		if unary, ok := value.(*ast.UnaryExpr); ok && unary.Op == token.AND {
			return true
		}
	}
	return false
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
