package analyzer_test

import (
	"path/filepath"
	"testing"

	"github.com/SuperSmile0426/gno-sentinel/internal/analyzer"
)

func TestFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		wantRule  string
		wantCount int
	}{
		{"payment vulnerable", "payment/vulnerable", "GNO-PAY-001", 1},
		{"payment fixed", "payment/fixed", "GNO-PAY-001", 0},
		{"auth vulnerable", "auth/vulnerable", "GNO-AUTH-001", 1},
		{"auth fixed", "auth/fixed", "GNO-AUTH-001", 0},
		{"state vulnerable", "state/vulnerable", "GNO-STATE-001", 1},
		{"state fixed", "state/fixed", "GNO-STATE-001", 0},
		{"realm vulnerable", "realm/vulnerable", "GNO-REALM-001", 1},
		{"realm fixed", "realm/fixed", "GNO-REALM-001", 0},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := filepath.Join("..", "..", "testdata", tc.path)
			findings, err := analyzer.New().ScanPath(root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := 0
			for _, f := range findings {
				if f.RuleID == tc.wantRule {
					got++
				}
			}
			if got != tc.wantCount {
				t.Fatalf("%s: got %d %s findings, want %d; all findings=%v", tc.name, got, tc.wantRule, tc.wantCount, findings)
			}
		})
	}
}
