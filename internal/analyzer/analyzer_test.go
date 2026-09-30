package analyzer_test

import (
	"path/filepath"
	"testing"

	"github.com/SuperSmile0426/gno-sentinel/internal/analyzer"
	"github.com/SuperSmile0426/gno-sentinel/internal/model"
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
		{"payment fixed rejecting guard", "payment/fixed", "GNO-PAY-001", 0},
		{"payment unrelated earlier check still vulnerable", "payment/unrelated-check-vulnerable", "GNO-PAY-001", 1},
		{"payment positive guarded branch", "payment/positive-guard-fixed", "GNO-PAY-001", 0},
		{"payment AssertOriginCall guard", "payment/assert-origin-fixed", "GNO-PAY-001", 0},
		{"payment local helper guard", "payment/helper-guard-fixed", "GNO-PAY-001", 0},
		{"auth vulnerable", "auth/vulnerable", "GNO-AUTH-001", 1},
		{"auth alias vulnerable", "auth/alias-vulnerable", "GNO-AUTH-001", 1},
		{"auth fixed", "auth/fixed", "GNO-AUTH-001", 0},
		{"auth benign origin use", "auth/benign-origin-fixed", "GNO-AUTH-001", 0},
		{"state vulnerable", "state/vulnerable", "GNO-STATE-001", 1},
		{"state fixed", "state/fixed", "GNO-STATE-001", 0},
		{"state cross-file vulnerable", "state/crossfile-vulnerable", "GNO-STATE-001", 1},
		{"state cross-file fixed", "state/crossfile-fixed", "GNO-STATE-001", 0},
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

func TestFindingMetadataAndExcerpt(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "auth", "vulnerable")
	a := analyzer.NewWithOptions(analyzer.Options{Metadata: model.AnalysisMetadata{
		GnoVersion: "v-test",
		Network:    "testnet",
	}})
	findings, err := a.ScanPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.GnoVersion != "v-test" || f.Network != "testnet" {
		t.Fatalf("metadata not propagated: %+v", f)
	}
	if f.SourceExcerpt == "" {
		t.Fatalf("expected source excerpt: %+v", f)
	}
}

func TestStableFindingOrder(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	a := analyzer.New()
	first, err := a.ScanPath(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.ScanPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("finding count changed: %d != %d", len(first), len(second))
	}
	for i := range first {
		if first[i].File != second[i].File || first[i].Line != second[i].Line || first[i].Column != second[i].Column || first[i].RuleID != second[i].RuleID {
			t.Fatalf("finding order unstable at %d: %+v != %+v", i, first[i], second[i])
		}
	}
}
