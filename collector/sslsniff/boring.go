package sslsniff

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"
)

type BoringSSLProbe struct {
	links []link.Link
	obj   *boringObjects
	rb    *ringbuf.Reader
}

func NewBoringSSLProbe(path string) (*BoringSSLProbe, error) {
	links, obj, err := addBoringProbe(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create BoringSSL probe: %w", err)
	}
	rb, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return nil, fmt.Errorf("failed to open BoringSSL ringbuf reader: %w", err)
	}
	return &BoringSSLProbe{
		links: links,
		obj:   obj,
		rb:    rb,
	}, nil
}

func (bp *BoringSSLProbe) ReadBuffer() (ringbuf.Record, error) {
	return bp.rb.Read()
}

func (bp *BoringSSLProbe) Close() error {
	var final error
	if err := bp.obj.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close BoringSSL eBPF objects: %w", err))
	}
	if err := bp.rb.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close BoringSSL ringbuf reader: %w", err))
	}
	for i, l := range bp.links {
		if err := l.Close(); err != nil {
			final = errors.Join(final, fmt.Errorf("failed to close %d-BoringSSL link: %w", i, err))
		}
	}
	return final
}

func addBoringProbe(path string) ([]link.Link, *boringObjects, error) {
	objs := boringObjects{}
	spec, err := ebpf.LoadCollectionSpec(boringSpecPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF BoringSSL spec: %w", err)
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load and assign eBPF objects: %w", err)
	}
	exec, err := link.OpenExecutable(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open BoringSSL file %s: %w", path, err)
	}
	links, err := attachBoringProbes(exec, &objs, path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to inject BoringSSL probes to %s: %w", path, err)
	}
	return links, &objs, nil
}

func attachBoringProbes(ex *link.Executable, objs *boringObjects, target string) ([]link.Link, error) {
	probes := []struct {
		address uint64
		prog    *ebpf.Program
		inject  func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{0x630bb90, objs.ProbeBoringSslReadEntry, ex.Uprobe},
		{0x630bb90, objs.ProbeBoringSslReadExit, ex.Uretprobe},
		{0x630c830, objs.ProbeBoringSslWriteExit, ex.Uprobe},
	}

	failed := 0
	links := []link.Link{}
	for _, probe := range probes {
		up, err := probe.inject("BoringSSL", probe.prog, &link.UprobeOptions{Address: probe.address})
		if err != nil {
			log.Warn().Str("target", target).Err(err).Uint64("addr", probe.address).Msg("failed to attach BoringSSL probe")
			failed++
			continue
		}
		links = append(links, up)
	}
	if failed > 0 {
		for _, link := range links {
			_ = link.Close()
		}
		return nil, fmt.Errorf("failed to inject %d/%d BoringSSL probe", failed, len(probes))
	}
	return links, nil
}
