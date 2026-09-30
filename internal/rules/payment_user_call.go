package rules

import (
	"go/ast"
	"go/token"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/source"
)

type PaymentUserCallRule struct{}

func (PaymentUserCallRule) ID() string { return "GNO-PAY-001" }

func (r PaymentUserCallRule) Analyze(ctx *Context) []model.Finding {
	var findings []model.Finding
	for _, file := range ctx.Package.Files {
		aliases := importAliases(file.AST, "chain/runtime/unsafe", "chain/banker")
		if len(aliases) == 0 {
			continue
		}
		for _, decl := range file.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			findings = append(findings, r.scanBlock(ctx, file, fn.Body, aliases, false)...)
		}
	}
	return findings
}

func (r PaymentUserCallRule) scanBlock(ctx *Context, file *source.File, block *ast.BlockStmt, aliases map[string]bool, guarded bool) []model.Finding {
	var findings []model.Finding
	currentGuard := guarded

	for _, stmt := range block.List {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok {
			if ifStmt.Init != nil {
				findings = append(findings, r.findOriginSends(ctx, file, ifStmt.Init, aliases, currentGuard)...)
			}
			findings = append(findings, r.findOriginSends(ctx, file, ifStmt.Cond, aliases, currentGuard)...)

			usesGuard, allowedWhenTrue := userCallCondition(ifStmt.Cond)
			if usesGuard {
				if allowedWhenTrue {
					findings = append(findings, r.scanBlock(ctx, file, ifStmt.Body, aliases, true)...)
					if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
						findings = append(findings, r.scanBlock(ctx, file, elseBlock, aliases, currentGuard)...)
					}
					continue
				}

				findings = append(findings, r.scanBlock(ctx, file, ifStmt.Body, aliases, currentGuard)...)
				if ifStmt.Else != nil {
					if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
						findings = append(findings, r.scanBlock(ctx, file, elseBlock, aliases, true)...)
					}
					continue
				}
				if blockTerminates(ifStmt.Body) {
					currentGuard = true
				}
				continue
			}

			findings = append(findings, r.scanBlock(ctx, file, ifStmt.Body, aliases, currentGuard)...)
			if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
				findings = append(findings, r.scanBlock(ctx, file, elseBlock, aliases, currentGuard)...)
			}
			continue
		}

		findings = append(findings, r.findOriginSends(ctx, file, stmt, aliases, currentGuard)...)
	}
	return findings
}

func (r PaymentUserCallRule) findOriginSends(ctx *Context, file *source.File, node ast.Node, aliases map[string]bool, guarded bool) []model.Finding {
	if guarded {
		return nil
	}
	var findings []model.Finding
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		if _, ok := n.(*ast.FuncLit); ok && n != node {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		receiver, name, ok := selectorCall(call)
		if !ok || name != "OriginSend" || !aliases[receiver] {
			return true
		}
		findings = append(findings, findingAt(ctx, file, call.Pos(), model.Finding{
			RuleID:     r.ID(),
			Title:      "OriginSend payment use lacks a dominating IsUserCall guard",
			Severity:   model.SeverityHigh,
			Confidence: "high",
			Evidence:   "OriginSend() is reachable without a recognized rejecting/direct-user control-flow guard",
			Explanation: "Current Gno security guidance requires payment entry points that rely on the origin-send envelope to verify a direct user call. " +
				"A merely earlier or unrelated IsUserCall() invocation is not enough; the check must actually constrain control flow before the payment envelope is trusted.",
			Remediation: "Use the Gno-version-appropriate direct-user-call guard so non-user paths terminate or cannot reach OriginSend(), then keep payment verification inside the guarded path.",
			References: []string{
				"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md",
				"https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md",
			},
			Applicability: "Current documented OriginSend direct-user-call security pattern; exact version boundaries not yet encoded.",
		}))
		return true
	})
	return findings
}

func userCallCondition(expr ast.Expr) (uses bool, allowedWhenTrue bool) {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.NOT && isDirectIsUserCall(e.X) {
			return true, false
		}
	case *ast.ParenExpr:
		return userCallCondition(e.X)
	}
	if isDirectIsUserCall(expr) {
		return true, true
	}
	return false, false
}

func isDirectIsUserCall(expr ast.Expr) bool {
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return isDirectIsUserCall(paren.X)
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	name, ok := callSelectorName(call)
	return ok && name == "IsUserCall"
}

func blockTerminates(block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return false
	}
	last := block.List[len(block.List)-1]
	switch stmt := last.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		call, ok := stmt.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := call.Fun.(*ast.Ident)
		return ok && id.Name == "panic"
	default:
		return false
	}
}
