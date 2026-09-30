package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/report"
)

func TestJSONIsMachineReadable(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{{RuleID: "GNO-TEST-001", Title: "test", Severity: model.SeverityHigh, Confidence: "high", File: "x.gno", Line: 1, Column: 2, Explanation: "x", Remediation: "y"}}
	if err := report.JSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Count != 1 {
		t.Fatalf("count=%d", decoded.Count)
	}
}
