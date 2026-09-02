.PHONY: all build test test-race policy-test clean

GO ?= go

all: build

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/gate ./cmd/gate
	ln -sf gate bin/gate-sh

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

policy-test:
	$(GO) run ./cmd/gate policy test

clean:
	rm -rf bin
