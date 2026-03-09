package sslsniff

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/internal/tool"
)

type RusTLSProbe struct {
	links []link.Link
	obj   *rustlsObjects
	rb    *ringbuf.Reader
}

func NewRusTLSProbe(rustlsPath *string) (*RusTLSProbe, error) {
	links, obj, err := addRustlsProbe(rustlsPath)
	if obj == nil || err != nil {
		return nil, err
	}
	rb, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return nil, fmt.Errorf("failed to open rustls ringbuf reader: %w", err)
	}
	return &RusTLSProbe{
		links: links,
		obj:   obj,
		rb:    rb,
	}, nil
}

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

func addRustlsProbe(rustlsPath *string) ([]link.Link, *rustlsObjects, error) {
	if rustlsPath == nil || len(*rustlsPath) == 0 {
		return nil, nil, nil
	}
	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Str("path", *rustlsPath).Value()
	if ok, err := tool.IsFilePath(*rustlsPath); err != nil || !ok {
		return nil, nil, fmt.Errorf("invalid rustls file path: %w", err)
	}
	logger.Info().Msg("using rustls")
	obj := rustlsObjects{}
	rustSpec, err := ebpf.LoadCollectionSpec(rustlsSpecPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load rustls eBPF spec: %w", err)
	}
	if err := rustSpec.LoadAndAssign(&obj, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load and assign rustls eBPF objects: %w", err)
	}
	exec, err := link.OpenExecutable(*rustlsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open rustls executable: %w", err)
	}
	links, err := attachRustlsProbes(exec, &obj, *rustlsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to attach rustls probes")
	}
	logger.Info().Msg("attaching rustls uprobes")
	return links, &obj, nil
}

func attachRustlsProbes(ex *link.Executable, objs *rustlsObjects, target string) ([]link.Link, error) {
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
	links := []link.Link{}
	for _, probe := range probes {
		up, err := probe.inject("rustls", probe.prog, &link.UprobeOptions{Address: probe.address})
		if err != nil {
			log.Warn().Str("target", target).Err(err).Msgf("failed to attach rustls probe %d", probe.address)
			failedProbes++
			continue
		}
		links = append(links, up)
	}
	if failedProbes > 0 {
		for _, link := range links {
			_ = link.Close()
		}
		return nil, fmt.Errorf("failed to inject %d/%d rustls probes", failedProbes, len(probes))
	}
	return links, nil
}
