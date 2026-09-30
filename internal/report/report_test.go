package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SuperSmile0426/gno-sentinel/internal/model"
	"github.com/SuperSmile0426/gno-sentinel/internal/report"
)

func TestJSONIsMachineReadableAndPreservesMetadata(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{{
		RuleID: "GNO-TEST-001", Title: "test", Severity: model.SeverityHigh, Confidence: "high",
		File: "x.gno", Line: 1, Column: 2, SourceExcerpt: "unsafe.Call()", Explanation: "x", Remediation: "y",
		GnoVersion: "v1.2.3", Network: "testnet",
	}}
	if err := report.JSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Count    int             `json:"count"`
		Findings []model.Finding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Count != 1 || decoded.Findings[0].GnoVersion != "v1.2.3" || decoded.Findings[0].Network != "testnet" {
		t.Fatalf("unexpected decoded result: %+v", decoded)
	}
}

func TestTextIncludesContextWhenProvided(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{{
		RuleID: "GNO-TEST-001", Title: "test", Severity: model.SeverityHigh, Confidence: "high",
		File: "x.gno", Line: 1, Column: 2, Explanation: "x", Remediation: "y", GnoVersion: "v1", Network: "n1",
	}}
	if err := report.Text(&buf, findings); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Context: gno=v1 network=n1") {
		t.Fatalf("context missing from text output: %s", buf.String())
	}
}
