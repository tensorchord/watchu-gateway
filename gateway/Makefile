BIN_DIR := bin
CMDS := $(wildcard cmd/*)
BINS := $(patsubst cmd/%,$(BIN_DIR)/%,$(CMDS))

build: $(BINS)

$(BIN_DIR)/%: cmd/%
	@rm -rf ${BIN_DIR}
	@mkdir -p $(BIN_DIR)
	GOFLAGS="-trimpath" go build -o $@ ./$<

run:
ifndef DATABASE_URL
	$(error DATABASE_URL is not set)
endif
	go run ./cmd/gateway

test:
	go test ./...

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

lint:
	golangci-lint run ./...

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
