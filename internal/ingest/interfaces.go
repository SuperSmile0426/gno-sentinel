package ingest

import "context"

type PackageEvent struct {
	Network     string
	GnoVersion  string
	Height      int64
	TxHash      string
	Creator     string
	PackagePath string
	Source      map[string]string
}

type TransactionEvent struct {
	Network    string
	GnoVersion string
	Height     int64
	TxHash     string
	Success    bool
	GasUsed    int64
	Message    string
}

type ChainFeed interface {
	SubscribePackages(context.Context) (<-chan PackageEvent, error)
	SubscribeTransactions(context.Context) (<-chan TransactionEvent, error)
}
