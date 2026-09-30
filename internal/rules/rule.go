package rules

import (
	"go/ast"
	"go/token"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
)

type Context struct {
	Path   string
	Source []byte
	Fset   *token.FileSet
	File   *ast.File
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
