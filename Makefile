.PHONY: help build build-all push push-all \
	build-collector build-gateway build-frontend build-skill-runner \
	push-collector push-gateway push-frontend push-skill-runner \
	login

# Default image repository (can be overridden via environment variable)
REPO ?= ghcr.io/tensorchord
VERSION ?= latest

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Environment Variables:"
	@echo "  REPO       - Image repository (default: $(REPO))"
	@echo "  VERSION    - Image tag (default: $(VERSION))"
	@echo ""
	@echo "Available targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/  /'

## Build targets
build-all: build-collector build-gateway build-frontend build-skill-runner ## Build all images

build-collector: ## Build collector image
	@echo "Building collector:$(VERSION)..."
	docker build -t $(REPO)/watchu-collector:$(VERSION) -f collector/Dockerfile collector

build-gateway: ## Build gateway image
	@echo "Building gateway:$(VERSION)..."
	docker build -t $(REPO)/watchu-gateway:$(VERSION) -f gateway/Dockerfile gateway

build-frontend: ## Build frontend image (production)
	@echo "Building frontend:$(VERSION)..."
	docker build --target prod -t $(REPO)/watchu-frontend:$(VERSION) -f frontend/Dockerfile frontend

build-skill-runner: ## Build skill-runner image
	@echo "Building skill-runner:$(VERSION)..."
	docker build -t $(REPO)/watchu-skill-runner:$(VERSION) -f skill-runner/Dockerfile .

## Push targets
push-all: push-collector push-gateway push-frontend push-skill-runner ## Push all images

push-collector: build-collector ## Push collector image
	@echo "Pushing collector:$(VERSION)..."
	docker push $(REPO)/watchu-collector:$(VERSION)

push-gateway: build-gateway ## Push gateway image
	@echo "Pushing gateway:$(VERSION)..."
	docker push $(REPO)/watchu-gateway:$(VERSION)

push-frontend: build-frontend ## Push frontend image
	@echo "Pushing frontend:$(VERSION)..."
	docker push $(REPO)/watchu-frontend:$(VERSION)

push-skill-runner: build-skill-runner ## Push skill-runner image
	@echo "Pushing skill-runner:$(VERSION)..."
	docker push $(REPO)/watchu-skill-runner:$(VERSION)

## Utility targets
login: ## Login to container registry
	@echo "Logging in to $(REPO)..."
	@echo "Usage: make login REGISTRY=<username>"
	docker login $(REPO)

## Alias for backward compatibility
build: build-all
push: push-all
