.PHONY: all build test test-race policy-test distribution-test clean

GO ?= go

all: build

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/gate ./cmd/gate
	ln -sf gate bin/gate-sh

test: distribution-test
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

policy-test:
	$(GO) run ./cmd/gate policy test

distribution-test:
	sh -n install.sh update-nethserver-admin scripts/build-release.sh scripts/test-distribution.sh
	sh scripts/test-distribution.sh

clean:
	rm -rf bin
