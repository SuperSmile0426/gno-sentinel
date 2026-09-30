package rules

import (
	"go/ast"
	"go/token"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
)

type PaymentUserCallRule struct{}

func (PaymentUserCallRule) ID() string { return "GNO-PAY-001" }

func (r PaymentUserCallRule) Analyze(ctx *Context) []model.Finding {
	var findings []model.Finding

	for _, decl := range ctx.File.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		var originSends []*ast.CallExpr
		var userGuards []token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := callSelectorName(call)
			if !ok {
				return true
			}
			switch name {
			case "OriginSend":
				originSends = append(originSends, call)
			case "IsUserCall":
				userGuards = append(userGuards, call.Pos())
			}
			return true
		})

		for _, send := range originSends {
			guarded := false
			for _, pos := range userGuards {
				if pos < send.Pos() {
					guarded = true
					break
				}
			}
			if guarded {
				continue
			}

			p := ctx.Fset.Position(send.Pos())
			findings = append(findings, model.Finding{
				RuleID:     r.ID(),
				Title:      "OriginSend payment use lacks a preceding IsUserCall guard",
				Severity:   model.SeverityHigh,
				Confidence: "high",
				File:       ctx.Path,
				Line:       p.Line,
				Column:     p.Column,
				Evidence:   "OriginSend() is used before any IsUserCall() call in the same function",
				Explanation: "Current Gno security guidance requires payment entry points that rely on the origin-send envelope to verify a direct user call. " +
					"Weaker or missing guards can make payment verification unsafe across intermediary/ephemeral call paths.",
				Remediation: "Guard the payment entry point with the current Gno-recommended direct-user-call check before reading OriginSend(), then verify the exact pattern against the Gno version you target.",
				References: []string{
					"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md",
					"https://github.com/gnolang/gno/blob/master/docs/resources/gno-ai-contract-review.md",
				},
			})
		}
	}

	return findings
}
