package rules

import (
	"go/ast"
	"go/token"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
)

type OriginCallerAuthRule struct{}

func (OriginCallerAuthRule) ID() string { return "GNO-AUTH-001" }

func (r OriginCallerAuthRule) Analyze(ctx *Context) []model.Finding {
	var findings []model.Finding
	for _, file := range ctx.Package.Files {
		aliases := importAliases(file.AST, "chain/runtime/unsafe")
		if len(aliases) == 0 {
			continue
		}
		for _, decl := range file.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			originVars := originCallerAliases(fn.Body, aliases)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				bin, ok := n.(*ast.BinaryExpr)
				if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
					return true
				}
				pos := originCallerInExpr(bin.X, aliases, originVars)
				if pos == token.NoPos {
					pos = originCallerInExpr(bin.Y, aliases, originVars)
				}
				if pos == token.NoPos {
					return true
				}
				findings = append(findings, findingAt(ctx, file, pos, model.Finding{
					RuleID:     r.ID(),
					Title:      "OriginCaller is used as authorization identity",
					Severity:   model.SeverityHigh,
					Confidence: "high",
					Evidence:   "OriginCaller-derived identity participates in a direct equality/inequality authorization-style comparison",
					Explanation: "Gno's transaction-origin caller primitive should not be treated as a general immediate-caller authorization primitive. " +
						"Cross-realm call semantics require realm-aware caller validation for protected actions.",
					Remediation: "Use the current realm/crossing API recommended by the target Gno version to derive and validate the immediate caller, and reserve transaction-origin primitives only for cases explicitly designed for them.",
					References: []string{
						"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md",
						"https://github.com/gnolang/gno/blob/master/docs/resources/gno-interrealm.md",
					},
					Applicability: "Current documented caller-identity security guidance; exact historical version boundaries not yet encoded.",
				}))
				return true
			})
		}
	}
	return findings
}

func originCallerAliases(body *ast.BlockStmt, unsafeAliases map[string]bool) map[string]bool {
	vars := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if !exprContainsUnsafeOriginCaller(rhs, unsafeAliases) {
					continue
				}
				if i < len(node.Lhs) {
					if id, ok := node.Lhs[i].(*ast.Ident); ok {
						vars[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range node.Values {
				if !exprContainsUnsafeOriginCaller(rhs, unsafeAliases) {
					continue
				}
				if i < len(node.Names) {
					vars[node.Names[i].Name] = true
				}
			}
		}
		return true
	})
	return vars
}

func originCallerInExpr(expr ast.Expr, unsafeAliases, originVars map[string]bool) token.Pos {
	var pos token.Pos
	ast.Inspect(expr, func(n ast.Node) bool {
		if pos != token.NoPos {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			receiver, name, ok := selectorCall(node)
			if ok && name == "OriginCaller" && unsafeAliases[receiver] {
				pos = node.Pos()
				return false
			}
		case *ast.Ident:
			if originVars[node.Name] {
				pos = node.Pos()
				return false
			}
		}
		return true
	})
	return pos
}

func exprContainsUnsafeOriginCaller(expr ast.Expr, unsafeAliases map[string]bool) bool {
	return originCallerInExpr(expr, unsafeAliases, nil) != token.NoPos
}
