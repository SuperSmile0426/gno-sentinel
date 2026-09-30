package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
)

func JSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Findings []model.Finding `json:"findings"`
		Count    int             `json:"count"`
	}{Findings: findings, Count: len(findings)})
}

func Text(w io.Writer, findings []model.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "%s %s [%s/%s]\n%s:%d:%d\n  %s\n  Fix: %s\n\n",
			f.RuleID, f.Title, f.Severity, f.Confidence, f.File, f.Line, f.Column, f.Explanation, f.Remediation); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%d finding(s)\n", len(findings))
	return err
}
