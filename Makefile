.PHONY: test vet fmt scan build check

fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

vet:
	go vet ./...

scan:
	go run ./cmd/gno-sentinel scan ./testdata

build:
	mkdir -p bin
	go build -o bin/gno-sentinel ./cmd/gno-sentinel

check: fmt test vet scan
