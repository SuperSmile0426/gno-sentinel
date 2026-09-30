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
	guardHelpers := directUserGuardHelpers(ctx.Package)
	var findings []model.Finding

	for _, file := range ctx.Package.Files {
		originAliases := importAliases(file.AST, "chain/runtime/unsafe", "chain/banker")
		if len(originAliases) == 0 {
			continue
		}
		runtimeAliases := importAliases(file.AST, "chain/runtime")

		for _, decl := range file.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			findings = append(findings, r.scanBlock(
				ctx,
				file,
				fn.Body,
				originAliases,
				runtimeAliases,
				guardHelpers,
				false,
			)...)
		}
	}
	return findings
}

func (r PaymentUserCallRule) scanBlock(
	ctx *Context,
	file *source.File,
	block *ast.BlockStmt,
	originAliases map[string]bool,
	runtimeAliases map[string]bool,
	guardHelpers map[string]bool,
	guarded bool,
) []model.Finding {
	var findings []model.Finding
	currentGuard := guarded

	for _, stmt := range block.List {
		if isDirectUserGuardStatement(stmt, runtimeAliases, guardHelpers) {
			currentGuard = true
			continue
		}

		if ifStmt, ok := stmt.(*ast.IfStmt); ok {
			if ifStmt.Init != nil {
				findings = append(findings, r.findOriginSends(ctx, file, ifStmt.Init, originAliases, currentGuard)...)
			}
			findings = append(findings, r.findOriginSends(ctx, file, ifStmt.Cond, originAliases, currentGuard)...)

			usesGuard, allowedWhenTrue := userCallCondition(ifStmt.Cond)
			if usesGuard {
				if allowedWhenTrue {
					findings = append(findings, r.scanBlock(
						ctx, file, ifStmt.Body, originAliases, runtimeAliases, guardHelpers, true,
					)...)
					if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
						findings = append(findings, r.scanBlock(
							ctx, file, elseBlock, originAliases, runtimeAliases, guardHelpers, currentGuard,
						)...)
					}
					continue
				}

				findings = append(findings, r.scanBlock(
					ctx, file, ifStmt.Body, originAliases, runtimeAliases, guardHelpers, currentGuard,
				)...)
				if ifStmt.Else != nil {
					if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
						findings = append(findings, r.scanBlock(
							ctx, file, elseBlock, originAliases, runtimeAliases, guardHelpers, true,
						)...)
					}
					continue
				}
				if blockTerminates(ifStmt.Body) {
					currentGuard = true
				}
				continue
			}

			findings = append(findings, r.scanBlock(
				ctx, file, ifStmt.Body, originAliases, runtimeAliases, guardHelpers, currentGuard,
			)...)
			if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
				findings = append(findings, r.scanBlock(
					ctx, file, elseBlock, originAliases, runtimeAliases, guardHelpers, currentGuard,
				)...)
			}
			continue
		}

		findings = append(findings, r.findOriginSends(ctx, file, stmt, originAliases, currentGuard)...)
	}
	return findings
}

func (r PaymentUserCallRule) findOriginSends(
	ctx *Context,
	file *source.File,
	node ast.Node,
	originAliases map[string]bool,
	guarded bool,
) []model.Finding {
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
		if !ok || name != "OriginSend" || !originAliases[receiver] {
			return true
		}
		findings = append(findings, findingAt(ctx, file, call.Pos(), model.Finding{
			RuleID:     r.ID(),
			Title:      "OriginSend payment use lacks a dominating direct-user guard",
			Severity:   model.SeverityHigh,
			Confidence: "high",
			Evidence:   "OriginSend() is reachable without a recognized rejecting/direct-user control-flow guard",
			Explanation: "Current Gno security guidance requires payment entry points that rely on the origin-send envelope to verify a direct user call. " +
				"A merely earlier or unrelated IsUserCall() invocation is not enough; the check must actually constrain control flow before the payment envelope is trusted.",
			Remediation: "Use the Gno-version-appropriate direct-user-call guard so non-user paths terminate or cannot reach OriginSend(), then keep payment verification inside the guarded path.",
			References: []string{
				"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md",
				"https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md",
				"https://github.com/gnolang/gno/blob/master/docs/resources/effective-gno.md",
			},
			Applicability: "Current documented OriginSend direct-user-call security pattern; exact version boundaries not yet encoded.",
		}))
		return true
	})
	return findings
}

func directUserGuardHelpers(pkg *source.Package) map[string]bool {
	helpers := map[string]bool{}
	for _, file := range pkg.Files {
		for _, decl := range file.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil || !hasRealmParam(fn.Type) {
				continue
			}
			for _, stmt := range fn.Body.List {
				ifStmt, ok := stmt.(*ast.IfStmt)
				if !ok || ifStmt.Else != nil {
					continue
				}
				usesGuard, allowedWhenTrue := userCallCondition(ifStmt.Cond)
				if usesGuard && !allowedWhenTrue && blockTerminates(ifStmt.Body) {
					helpers[fn.Name.Name] = true
					break
				}
			}
		}
	}
	return helpers
}

func isDirectUserGuardStatement(
	stmt ast.Stmt,
	runtimeAliases map[string]bool,
	guardHelpers map[string]bool,
) bool {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	if !ok {
		return false
	}

	if id, ok := call.Fun.(*ast.Ident); ok && guardHelpers[id.Name] {
		return true
	}
	receiver, name, ok := selectorCall(call)
	return ok && name == "AssertOriginCall" && runtimeAliases[receiver]
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
