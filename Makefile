.DEFAULT_GOAL := build

update_header:
	@bash headers/update.sh

build:
	@go generate ./...
	@go build -o bin/sslsniff ./sslsniff
	@go build -o bin/app ./main.go

format:
	@go fmt ./...
	@find . -type f -name "*.c" | xargs clang-format -i
