.PHONY: clean build install uninstall run run-secure fmt test lint help dev-tools docker-build docker-run docker-run-secure docker-shell release version

BINARY_NAME=mcp-shell
BUILD_DIR=bin
IMAGE_NAME=mcp-shell
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_HASH?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u '+%Y-%m-%d_%H:%M:%S')

help:
	@echo "mcp-shell development commands:"
	@echo "Version: $(VERSION)"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT_HASH)"
	@echo "Build Time: $(BUILD_TIME)"

build: deps
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build \
		-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH) -X main.buildTime=$(BUILD_TIME) -s -w -extldflags '-static'" \
		-a -installsuffix cgo \
		-o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME) ($(VERSION))"

clean:
	rm -rf $(BUILD_DIR)
	go clean
	docker rmi $(IMAGE_NAME):$(VERSION) 2>/dev/null || true
	docker rmi $(IMAGE_NAME):latest 2>/dev/null || true
	@echo "Cleaned build artifacts and Docker images"

deps:
	go mod tidy
	@echo "Dependencies installed"

install: build
	install -c $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed $(BINARY_NAME) to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstalled $(BINARY_NAME) from /usr/local/bin/"

run:
	CGO_ENABLED=0 go run -ldflags "-X main.version=$(VERSION) -s -w" .

run-secure:
	@echo 'security:' > .temp-config.yaml
	@echo '  enabled: true' >> .temp-config.yaml
	@echo '  allowed_commands: [ls, cat, grep, find, echo, pwd]' >> .temp-config.yaml
	@echo '  blocked_commands: [rm -rf, sudo, chmod 777]' >> .temp-config.yaml
	@echo '  blocked_patterns: ["rm\\s+.*-rf.*", "sudo\\s+.*"]' >> .temp-config.yaml
	@echo '  max_execution_time: 30s' >> .temp-config.yaml
	@echo '  working_directory: /tmp/mcp-workspace' >> .temp-config.yaml
	@echo '  max_output_size: 1048576' >> .temp-config.yaml
	@echo '  audit_log: true' >> .temp-config.yaml
	CGO_ENABLED=0 MCP_SHELL_SEC_CONFIG_FILE=.temp-config.yaml go run -ldflags "-X main.version=$(VERSION) -s -w" .
	@rm -f .temp-config.yaml

fmt:
	gofmt -w .
	@command -v goimports >/dev/null 2>&1 && goimports -w . || echo "goimports not found, install with: make dev-tools"
	@command -v golines >/dev/null 2>&1 && golines -w . || echo "golines not found, install with: make dev-tools"
	@echo "Code formatted"

test:
	go test -v ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not found, install from https://golangci-lint.run/"

dev-tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/segmentio/golines@latest
	@command -v jq >/dev/null 2>&1 || (echo "Installing jq..." && \
		case "$$(uname -s)" in \
			Linux*) sudo apt-get update && sudo apt-get install -y jq || sudo yum install -y jq ;; \
			Darwin*) brew install jq ;; \
			*) echo "Please install jq manually" ;; \
		esac)
	@echo "Development tools installed"

docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):latest .
	@echo "Docker image built: $(IMAGE_NAME):$(VERSION)"

docker-run:
	docker run -it --rm \
		-v /tmp/mcp-workspace:/tmp/mcp-workspace \
		$(IMAGE_NAME):$(VERSION)

docker-run-secure:
	docker run -it --rm \
		-v /tmp/mcp-workspace:/tmp/mcp-workspace \
		-e MCP_SHELL_LOG_LEVEL=info \
		$(IMAGE_NAME):$(VERSION)

docker-shell:
	docker run -it --rm \
		-v /tmp/mcp-workspace:/tmp/mcp-workspace \
		--entrypoint /bin/bash \
		$(IMAGE_NAME):$(VERSION)

release: clean build docker-build
	@echo "Release build complete:"
	@echo "  Binary: $(BUILD_DIR)/$(BINARY_NAME) ($(VERSION))"
	@echo "  Docker: $(IMAGE_NAME):$(VERSION)"
