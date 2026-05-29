.PHONY: build build-all test test-e2e lint lint-no-beta-urls lint-secret-leak clean

BINARY_NAME := epack-collector-microsoft-cloud
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --verify HEAD 2>/dev/null || echo "unknown")
GOLANGCI_LINT_VERSION := v2.9.0
GOLANGCI_LINT := ./bin/golangci-lint

build:
	go build -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME) ./cmd/$(BINARY_NAME)

build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-linux-amd64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-linux-arm64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-darwin-amd64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/$(BINARY_NAME)

test:
	go test -race -v ./...

test-e2e:
	go test -tags=e2e -v ./internal/collector/...

$(GOLANGCI_LINT):
	mkdir -p ./bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh -o ./bin/golangci-lint-install.sh
	sh ./bin/golangci-lint-install.sh -b ./bin $(GOLANGCI_LINT_VERSION)
	rm -f ./bin/golangci-lint-install.sh

lint: $(GOLANGCI_LINT) lint-no-beta-urls lint-secret-leak
	$(GOLANGCI_LINT) run ./...

lint-no-beta-urls:
	./scripts/check-no-beta-urls.sh

lint-secret-leak: build
	./scripts/check-secret-leak.sh ./$(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*
