.PHONY: clean build install run fmt test lint help dev-tools

BINARY_NAME=mcp-shell
BUILD_DIR=bin
VERSION?=0.2.0

help: ## Show this help message
	@echo "mcp-shell development commands:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the binary
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)
	go clean
	@echo "Cleaned build artifacts"

install: ## Install and update dependencies
	go mod tidy
	go mod download
	@echo "Dependencies installed"

run: ## Run the application
	go run .

fmt: ## Format the code
	gofmt -w .
	@command -v goimports >/dev/null 2>&1 && goimports -w . || echo "goimports not found, install with: make dev-tools"
	@command -v golines >/dev/null 2>&1 && golines -w . || echo "golines not found, install with: make dev-tools"
	@echo "Code formatted"

test: ## Run tests
	go test -v ./...

lint: ## Run linter (requires golangci-lint)
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not found, install from https://golangci-lint.run/"

dev-tools: ## Install development tools
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/segmentio/golines@latest
	@echo "Development tools installed"

release: clean build ## Clean and build for release
	@echo "Release build complete: $(BUILD_DIR)/$(BINARY_NAME)"
