.PHONY: clean build install run fmt test lint help dev-tools docker-build docker-run version

BINARY_NAME=mcp-shell
BUILD_DIR=bin
IMAGE_NAME=mcp-shell
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_HASH?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u '+%Y-%m-%d_%H:%M:%S')

help: ## Show this help message
	@echo "mcp-shell development commands:"
	@echo "Version: $(VERSION)"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT_HASH)"
	@echo "Build Time: $(BUILD_TIME)"

build: ## Build the binary with version info
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux go build \
		-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH) -X main.buildTime=$(BUILD_TIME) -s -w -extldflags '-static'" \
		-a -installsuffix cgo \
		-o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME) ($(VERSION))"

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)
	go clean
	docker rmi $(IMAGE_NAME):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_NAME):latest 2>/dev/null || true
	@echo "Cleaned build artifacts and Docker images"

install: ## Install and update dependencies
	go mod tidy
	go mod download
	@echo "Dependencies installed"

run: ## Run the application
	CGO_ENABLED=0 go run -ldflags "-X main.version=$(VERSION) -s -w" .

run-secure: ## Run with security configuration
	CGO_ENABLED=0 MCP_SHELL_CONFIG_FILE=config.example.json go run -ldflags "-X main.version=$(VERSION) -s -w" .

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
	@command -v jq >/dev/null 2>&1 || (echo "Installing jq..." && \
		case "$$(uname -s)" in \
			Linux*) sudo apt-get update && sudo apt-get install -y jq || sudo yum install -y jq ;; \
			Darwin*) brew install jq ;; \
			*) echo "Please install jq manually" ;; \
		esac)
	@echo "Development tools installed"

docker-build: ## Build Docker image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):latest .
	@echo "Docker image built: $(IMAGE_NAME):$(VERSION)"

docker-run: ## Run Docker container
	docker run -it --rm \
		-v /tmp/mcp-workspace:/tmp/mcp-workspace \
		$(IMAGE_NAME):$(VERSION)

docker-run-secure: ## Run Docker container with security config
	docker run -it --rm \
		-v /tmp/mcp-workspace:/tmp/mcp-workspace \
		-e MCP_SHELL_SECURITY_ENABLED=true \
		-e MCP_SHELL_LOG_LEVEL=info \
		$(IMAGE_NAME):$(VERSION)

docker-shell: ## Run Docker container with shell access
	docker run -it --rm \
		-v /tmp/mcp-workspace:/tmp/mcp-workspace \
		--entrypoint /bin/bash \
		$(IMAGE_NAME):$(VERSION)

release: clean build docker-build ## Clean, build, and create Docker image for release
	@echo "Release build complete:"
	@echo "  Binary: $(BUILD_DIR)/$(BINARY_NAME) ($(VERSION))"
	@echo "  Docker: $(IMAGE_NAME):$(VERSION)"

config-example: ## Generate example configuration
	@echo "Generating example configuration..."
	@jq '.' config.example.json > config.json 2>/dev/null || cp config.example.json config.json
	@echo "Example config saved to config.json"
