package rules

import (
	"go/ast"
	"strconv"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
)

type UnsafePreviousRealmRule struct{}

func (UnsafePreviousRealmRule) ID() string { return "GNO-REALM-001" }

func (r UnsafePreviousRealmRule) Analyze(ctx *Context) []model.Finding {
	unsafeAliases := map[string]bool{}
	for _, imp := range ctx.File.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != "chain/runtime/unsafe" {
			continue
		}
		name := "unsafe"
		if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
			name = imp.Name.Name
		}
		unsafeAliases[name] = true
	}
	if len(unsafeAliases) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, decl := range ctx.File.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !hasRealmParam(fn.Type) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "PreviousRealm" {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !unsafeAliases[id.Name] {
				return true
			}
			p := ctx.Fset.Position(call.Pos())
			findings = append(findings, model.Finding{
				RuleID:      r.ID(),
				Title:       "unsafe.PreviousRealm is used despite an available realm parameter",
				Severity:    model.SeverityHigh,
				Confidence:  "high",
				File:        ctx.Path,
				Line:        p.Line,
				Column:      p.Column,
				Evidence:    id.Name + ".PreviousRealm() inside a function accepting realm",
				Explanation: "Current Gno guidance treats the unsafe previous-realm API as inappropriate in crossing functions that already receive the frame-bound realm capability.",
				Remediation: "Derive caller identity from the function's realm parameter using the API required by the target Gno version; remove the unsafe previous-realm call.",
				References: []string{
					"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md",
					"https://github.com/gnolang/gno/blob/master/docs/resources/gno-interrealm.md",
				},
			})
			return true
		})
	}
	return findings
}

func hasRealmParam(ft *ast.FuncType) bool {
	if ft == nil || ft.Params == nil {
		return false
	}
	for _, field := range ft.Params.List {
		id, ok := field.Type.(*ast.Ident)
		if ok && id.Name == "realm" {
			return true
		}
	}
	return false
}
