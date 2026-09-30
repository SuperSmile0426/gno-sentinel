package model

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

type AnalysisMetadata struct {
	GnoVersion string `json:"gno_version,omitempty"`
	Network    string `json:"network,omitempty"`
}

type Finding struct {
	RuleID        string   `json:"rule_id"`
	Title         string   `json:"title"`
	Severity      Severity `json:"severity"`
	Confidence    string   `json:"confidence"`
	File          string   `json:"file"`
	Line          int      `json:"line"`
	Column        int      `json:"column"`
	Evidence      string   `json:"evidence,omitempty"`
	SourceExcerpt string   `json:"source_excerpt,omitempty"`
	Explanation   string   `json:"explanation"`
	Remediation   string   `json:"remediation"`
	References    []string `json:"references,omitempty"`
	Applicability string   `json:"applicability,omitempty"`
	GnoVersion    string   `json:"gno_version,omitempty"`
	Network       string   `json:"network,omitempty"`
}
