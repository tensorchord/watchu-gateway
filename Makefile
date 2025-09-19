update_header:
	@bash headers/update.sh

build:
	@go generate ./...
	@go build -o bin/app ./sslsniff

format:
	@go fmt ./...
	@find . -type f -name "*.c" | xargs clang-format -i
