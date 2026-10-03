.PHONY: prepare build test vet check audit dist
VERSION ?= 0.2.0
GOFLAGS := "-modfile=$(CURDIR)/.build/go.mod" -mod=readonly -buildvcs=false
GOWORK := off
export GOFLAGS GOWORK

prepare:
	GOFLAGS= python3 scripts/prepare_tailscale.py

build: prepare
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o plugin .

test: prepare
	python3 -m unittest discover -s scripts -p 'test_*.py'
	go test -race ./...
	go test -race tailscale.com/feature/acme -run '^TestSiloCustomStateStore'

vet: prepare
	go vet ./...

check: test vet
	test -z "$$(gofmt -l *.go internal scripts/acme_state_test.go.txt)"

# Scan published versions, including the locally adapted Tailscale dependency.
audit:
	GOWORK=off GOFLAGS= go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -scan package ./...

dist: prepare
	python3 scripts/dist.py $(VERSION)
