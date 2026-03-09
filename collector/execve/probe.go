//go:build amd64 && linux

package execve

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 exec exec.bpf.c -- -I../headers
