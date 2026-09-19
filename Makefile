# nexus Makefile
# Common targets: make build / make run / make tidy / make deps

BINARY  := nexus
BIN_DIR := bin
PKG     := ./...
GO      := go

# Version info (injected at build time into main.version / main.commitID / main.buildTime)
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT_ID  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commitID=$(COMMIT_ID) \
	-X main.buildTime=$(BUILD_TIME)

.DEFAULT_GOAL := build
.PHONY: help build run dev test vet fmt tidy deps clean install-tools proto proto-lint

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build to bin/nexus
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/nexus
	@echo "built -> $(BIN_DIR)/$(BINARY)"

run: ## Run directly (go run nexus start)
	$(GO) run -ldflags "$(LDFLAGS)" ./cmd/nexus start

dev: ## Run with debug level + json logs
	$(GO) run -ldflags "$(LDFLAGS)" ./cmd/nexus start --log-level debug --log-format json

test: ## Run tests (root module + gen/trueopen contract module)
	$(GO) test $(PKG)
	cd gen/trueopen && $(GO) test ./...

vet: ## go vet static checks (root module + gen/trueopen)
	$(GO) vet $(PKG)
	cd gen/trueopen && $(GO) vet ./...

fmt: ## Format (root module + gen/trueopen)
	$(GO) fmt $(PKG)
	cd gen/trueopen && $(GO) fmt ./...

tidy: ## Tidy go.mod / go.sum (after adding/removing deps; root module + gen/trueopen)
	$(GO) mod tidy
	cd gen/trueopen && $(GO) mod tidy

deps: ## Upgrade all deps to latest minor/patch and tidy
	$(GO) get -u $(PKG)
	$(GO) mod tidy

clean: ## Clean build outputs
	rm -rf $(BIN_DIR)
	$(GO) clean

proto: ## Generate protobuf/grpc code (buf generate)
	buf generate

proto-lint: ## Lint proto
	buf lint

install-tools: ## Install common dev tools (proto codegen + grpcurl)
	$(GO) install golang.org/x/tools/cmd/goimports@latest
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
	$(GO) install github.com/bufbuild/buf/cmd/buf@latest
	$(GO) install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
