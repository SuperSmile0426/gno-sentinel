package rules

import (
	"go/ast"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
)

type UnsafePreviousRealmRule struct{}

func (UnsafePreviousRealmRule) ID() string { return "GNO-REALM-001" }

func (r UnsafePreviousRealmRule) Analyze(ctx *Context) []model.Finding {
	var findings []model.Finding
	for _, file := range ctx.Package.Files {
		unsafeAliases := importAliases(file.AST, "chain/runtime/unsafe")
		if len(unsafeAliases) == 0 {
			continue
		}
		for _, decl := range file.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !hasRealmParam(fn.Type) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				receiver, name, ok := selectorCall(call)
				if !ok || name != "PreviousRealm" || !unsafeAliases[receiver] {
					return true
				}
				findings = append(findings, findingAt(ctx, file, call.Pos(), model.Finding{
					RuleID:      r.ID(),
					Title:       "unsafe.PreviousRealm is used despite an available realm parameter",
					Severity:    model.SeverityHigh,
					Confidence:  "high",
					Evidence:    receiver + ".PreviousRealm() inside a function accepting realm",
					Explanation: "Current Gno guidance treats the unsafe previous-realm API as inappropriate in crossing functions that already receive the frame-bound realm capability.",
					Remediation: "Derive caller identity from the function's realm parameter using the API required by the target Gno version; remove the unsafe previous-realm call.",
					References: []string{
						"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md",
						"https://github.com/gnolang/gno/blob/master/docs/resources/gno-interrealm.md",
					},
					Applicability: "Current documented realm/caller safety guidance; exact historical version boundaries not yet encoded.",
				}))
				return true
			})
		}
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
