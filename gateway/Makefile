BIN_DIR := bin
BIN := $(BIN_DIR)/gateway
PKG := ./cmd/gateway

build:
	@mkdir -p $(BIN_DIR)
	GOFLAGS="-trimpath" go build -o $(BIN) $(PKG)

run:
ifndef DATABASE_URL
	$(error DATABASE_URL is not set)
endif
	go run $(PKG)

test:
	go test ./...

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

lint:
	golangci-lint run

swagger:
	./scripts/generate-swagger.sh

docker-build:
	docker build -t watchu/gateway:latest .

compose-up: fmt lint test swagger
	docker compose up --build

compose-down:
	docker compose down

clean:
	rm -rf $(BIN_DIR)

atlas-migrate-hash:
	@atlas migrate hash --dir file://db/migrations