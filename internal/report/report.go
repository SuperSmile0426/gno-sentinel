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
		if _, err := fmt.Fprintf(w, "%s %s [%s/%s]\n%s:%d:%d\n", f.RuleID, f.Title, f.Severity, f.Confidence, f.File, f.Line, f.Column); err != nil {
			return err
		}
		if f.GnoVersion != "" || f.Network != "" {
			if _, err := fmt.Fprintf(w, "  Context: gno=%s network=%s\n", valueOrUnknown(f.GnoVersion), valueOrUnknown(f.Network)); err != nil {
				return err
			}
		}
		if f.SourceExcerpt != "" {
			if _, err := fmt.Fprintf(w, "  Source: %s\n", f.SourceExcerpt); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "  %s\n  Fix: %s\n\n", f.Explanation, f.Remediation); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%d finding(s)\n", len(findings))
	return err
}

func valueOrUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
