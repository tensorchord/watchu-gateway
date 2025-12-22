package sslsniff

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"
)

type RusTLSProbe struct {
	links []link.Link
	obj   *rustlsObjects
	rb    *ringbuf.Reader
}

func NewRusTLSProbe(rustlsPath *string) (*RusTLSProbe, error) {
	links := []link.Link{}
	rustlsObjs, err := addRustlsProbe(rustlsPath, &links)
	if rustlsObjs == nil || err != nil {
		return nil, err
	}
	rustlsRingBuffer, err := ringbuf.NewReader(rustlsObjs.Events)
	if err != nil {
		return nil, fmt.Errorf("failed to open rustls ringbuf reader: %w", err)
	}
	return &RusTLSProbe{
		links: links,
		obj:   rustlsObjs,
		rb:    rustlsRingBuffer,
	}, nil
}

func (rp *RusTLSProbe) Start(ctx context.Context) {}

func (rp *RusTLSProbe) ReadBuffer() (ringbuf.Record, error) {
	return rp.rb.Read()
}

func (rp *RusTLSProbe) Close() error {
	var final error
	if err := rp.obj.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close rustls eBPF objects: %w", err))
	}
	if err := rp.rb.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close rustls ringbuf reader: %w", err))
	}
	for i, l := range rp.links {
		if err := l.Close(); err != nil {
			final = errors.Join(final, fmt.Errorf("failed to close %d-rustls link: %w", i, err))
		}
	}
	return final
}

func addRustlsProbe(rustlsPath *string, links *[]link.Link) (*rustlsObjects, error) {
	if rustlsPath == nil || len(*rustlsPath) == 0 {
		return nil, nil
	}
	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Str("path", *rustlsPath).Value()
	if ok, err := isFilePath(*rustlsPath); err != nil || !ok {
		return nil, fmt.Errorf("invalid rustls file path: %w", err)
	}
	logger.Info().Msg("using rustls")
	rustObjs := rustlsObjects{}
	rustSpec, err := ebpf.LoadCollectionSpec(rustlsSpecPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load rustls eBPF spec: %w", err)
	}
	if err := rustSpec.LoadAndAssign(&rustObjs, nil); err != nil {
		return nil, fmt.Errorf("failed to load and assign rustls eBPF objects: %w", err)
	}
	exec, err := link.OpenExecutable(*rustlsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open rustls executable: %w", err)
	}
	if err = attachRustlsProbes(exec, &rustObjs, *rustlsPath, links); err != nil {
		return nil, fmt.Errorf("failed to attach rustls probes")
	}
	logger.Info().Msg("attaching rustls uprobes")
	return &rustObjs, nil
}

func attachRustlsProbes(ex *link.Executable, objs *rustlsObjects, target string, links *[]link.Link) error {
	probes := []struct {
		address uint64
		prog    *ebpf.Program
		inject  func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{0x27BFB60, objs.ProbeRustlsTokioPollReadEntry, ex.Uprobe},
		{0x27BFB60, objs.ProbeRustlsTokioPollReadExit, ex.Uretprobe},
		{0x27BFDD0, objs.ProbeRustlsTokioPollWriteEntry, ex.Uprobe},
	}

	failedProbes := 0
	newLinks := []link.Link{}
	for _, probe := range probes {
		up, err := probe.inject("rustls", probe.prog, &link.UprobeOptions{Address: probe.address})
		if err != nil {
			log.Warn().Str("target", target).Err(err).Msgf("failed to attach rustls probe %d", probe.address)
			failedProbes++
			continue
		}
		newLinks = append(newLinks, up)
	}
	if failedProbes > 0 {
		for _, link := range newLinks {
			_ = link.Close()
		}
		return fmt.Errorf("failed to inject %d/%d rustls probes", failedProbes, len(probes))
	}
	*links = append(*links, newLinks...)
	return nil
}
