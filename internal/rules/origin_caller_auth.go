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

	ast.Inspect(ctx.File, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
			return true
		}

		call := containsCallSelector(bin.X, "OriginCaller")
		if call == nil {
			call = containsCallSelector(bin.Y, "OriginCaller")
		}
		if call == nil {
			return true
		}

		p := ctx.Fset.Position(call.Pos())
		findings = append(findings, model.Finding{
			RuleID:     r.ID(),
			Title:      "OriginCaller is used directly as authorization identity",
			Severity:   model.SeverityHigh,
			Confidence: "high",
			File:       ctx.Path,
			Line:       p.Line,
			Column:     p.Column,
			Evidence:   "OriginCaller() appears inside a direct equality/inequality comparison",
			Explanation: "Gno's transaction-origin caller primitive should not be treated as a general immediate-caller authorization primitive. " +
				"Cross-realm call semantics require realm-aware caller validation for protected actions.",
			Remediation: "Use the current realm/crossing API recommended by the target Gno version to derive and validate the immediate caller, and reserve transaction-origin primitives only for cases explicitly designed for them.",
			References: []string{
				"https://github.com/gnolang/gno/blob/master/docs/resources/gno-security-guide.md",
				"https://github.com/gnolang/gno/blob/master/docs/resources/gno-interrealm.md",
			},
		})
		return true
	})

	return findings
}
