.PHONY: all build build-windows test test-race policy-test distribution-test clean

GO ?= go

all: build

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/gate ./cmd/gate
	ln -sf gate bin/gate-sh

build-windows:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -o bin/gate-windows-amd64.exe ./cmd/gate
	cp bin/gate-windows-amd64.exe bin/gate-sh.exe

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
