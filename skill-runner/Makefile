# Skill Runner Makefile
# Helps build agent Docker images, run the runner service, and run tests

# Variables
AGENT ?= claude-code
IMAGE_REGISTRY ?= ghcr.io/tensorchord
IMAGE_TAG ?= latest
AGENT_DIR := agents/$(AGENT)
FULL_IMAGE := $(IMAGE_REGISTRY)/watchu-$(AGENT)-agent:$(IMAGE_TAG)

GO_FILES := $(shell find . -name '*.go' -type f)

.PHONY: all
all: build

## build: Build the skill-runner binary
.PHONY: build
build:
	@echo "Building skill-runner binary..."
	CGO_ENABLED=0 go build -o bin/skill-runner ./cmd/runner

## build-agent: Build an agent Docker image (use AGENT=name, default: claude-code)
.PHONY: build-agent
build-agent:
	@echo "Building $(AGENT) agent Docker image..."
	docker build -t $(FULL_IMAGE) -f $(AGENT_DIR)/Dockerfile $(AGENT_DIR)
	@echo "Built $(FULL_IMAGE)"

## build-agent-local: Build agent with local tag for testing
.PHONY: build-agent-local
build-agent-local: IMAGE_TAG = local
build-agent-local: build-agent

## push-agent: Build and push an agent Docker image
.PHONY: push-agent
push-agent: build-agent
	@echo "Pushing $(FULL_IMAGE)..."
	docker push $(FULL_IMAGE)

## run: Run the skill-runner service locally
.PHONY: run
run: build
	@echo "Starting skill-runner on :8091..."
	./bin/skill-runner

## run-agent-docker: Test agent image with Docker runner mode
.PHONY: run-agent-docker
run-agent-docker: build build-agent-local
	@echo "Testing $(AGENT) agent image with Docker runner..."
	SKILL_RUNNER_DOCKER_IMAGE="$(IMAGE_REGISTRY)/watchu-$(AGENT)-agent:local" \
	./bin/skill-runner

## test: Run all tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

## test-coverage: Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run linter
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run ./... || true

## fmt: Format Go code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w . 2>/dev/null || true

## clean: Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html

## list-agents: List available agent directories
.PHONY: list-agents
list-agents:
	@echo "Available agents:"
	@ls -1 agents/ 2>/dev/null || echo "No agents found"

## help: Show this help message
.PHONY: help
help:
	@echo "Skill Runner Makefile"
	@echo ""
	@echo "Usage: make [target] [AGENT=name] [IMAGE_TAG=tag] [IMAGE_REGISTRY=registry]"
	@echo ""
	@echo "Examples:"
	@echo "  make build-agent              # Build claude-code agent (default)"
	@echo "  make build-agent AGENT=xxx    # Build agent xxx"
	@echo "  make push-agent AGENT=xxx IMAGE_TAG=v1.0.0"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

.DEFAULT_GOAL := help
