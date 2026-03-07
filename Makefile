SHELL := /bin/bash

BINARY ?= secryn
PKG ?= github.com/secryn/secryn-cli
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(PKG)/pkg/version.Version=$(VERSION) -X $(PKG)/pkg/version.Commit=$(COMMIT) -X $(PKG)/pkg/version.Date=$(DATE)

.PHONY: build test lint fmt tidy clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./

test:
	go test ./...

lint:
	go vet ./...

fmt:
	gofmt -w $$(find . -type f -name '*.go' -not -path './vendor/*')

tidy:
	go mod tidy

clean:
	rm -rf bin dist
