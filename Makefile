.DEFAULT_GOAL := build

update_header:
	@bash headers/update.sh

build:
	@go generate ./...
	@go build -o bin/app cmd/main.go

format:
	@go fmt ./...
	@golangci-lint fmt
	@find . -type f -name "*.c" | xargs clang-format -i

lint:
	@golangci-lint run
