.DEFAULT_GOAL := build

update_header:
	@bash headers/update.sh

gen_vmlinux:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

gen_ebpf:
	@go generate ./...

build: gen_ebpf
	@go build -o bin/app cmd/main.go

format:
	@go fmt ./...
	@golangci-lint fmt
	@find . -type f -name "*.c" | xargs clang-format -i

lint-ebpf:
	@find . -type f -name "*.c" | xargs clang-format --dry-run --Werror

lint-go:
	@golangci-lint run

lint: lint-ebpf lint-go
