# Build stage
FROM golang:1.25-alpine AS builder

# Install git for version info
RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Get version info
ARG VERSION=dev
ARG COMMIT_HASH
ARG BUILD_TIME

# Build the binary with static linking
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -s -w -extldflags '-static'" \
    -a -installsuffix cgo \
    -o mcp-shell .

# Runtime stage
FROM alpine:3.22

# Install essential packages (fixed package names for Alpine)
RUN apk add --no-cache \
    bash \
    curl \
    wget \
    git \
    make \
    findutils \
    grep \
    sed \
    gawk \
    tar \
    gzip \
    unzip \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1000 mcpuser && \
    adduser -D -s /bin/bash -u 1000 -G mcpuser mcpuser

# Create workspace directory
RUN mkdir -p /tmp/mcp-workspace && \
    chown mcpuser:mcpuser /tmp/mcp-workspace

# Create config directory
RUN mkdir -p /etc/mcp-shell && \
    chown mcpuser:mcpuser /etc/mcp-shell

# Copy binary from builder stage
COPY --from=builder /app/mcp-shell /usr/local/bin/mcp-shell
RUN chmod +x /usr/local/bin/mcp-shell

# Copy example security config
COPY security.yaml /etc/mcp-shell/security.yaml


# Set environment
ENV MCP_SHELL_SEC_CONFIG_FILE=/etc/mcp-shell/security.yaml
ENV PATH="/usr/local/bin:${PATH}"

# Switch to non-root user
USER mcpuser
WORKDIR /tmp/mcp-workspace

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD echo '{"jsonrpc": "2.0", "method": "ping", "id": 1}' | timeout 2 mcp-shell || exit 1

ENTRYPOINT ["mcp-shell"]
