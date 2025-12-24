package sslsniff

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/internal/container"
	"github.com/tensorchord/watchu/collector/internal/tool"
)

const MAX_DYNAMIC_CHANNEL_SIZE = 16

func attachSSLProbes(ex *link.Executable, objs *sslObjects, target string, links *[]link.Link) error {
	probes := []struct {
		symbol string
		prog   *ebpf.Program
		inject func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{"SSL_read", objs.ProbeSslReadEntry, ex.Uprobe},
		{"SSL_read", objs.ProbeSslReadExit, ex.Uretprobe},
		{"SSL_read_ex", objs.ProbeSslReadExEntry, ex.Uprobe},
		{"SSL_read_ex", objs.ProbeSslReadExExit, ex.Uretprobe},
		{"SSL_write", objs.ProbeSslReadEntry, ex.Uprobe},
		{"SSL_write", objs.ProbeSslWriteExit, ex.Uretprobe},
		{"SSL_write_ex", objs.ProbeSslReadExEntry, ex.Uprobe},
		{"SSL_write_ex", objs.ProbeSslWriteExExit, ex.Uretprobe},
	}

	failedProbes := 0
	newLinks := []link.Link{}
	for _, probe := range probes {
		up, err := probe.inject(probe.symbol, probe.prog, nil)
		if err != nil {
			log.Warn().Str("target", target).Err(err).Msgf("failed to attach probe %s", probe.symbol)
			failedProbes++
			continue
		}
		newLinks = append(newLinks, up)
	}
	if failedProbes > 0 {
		for _, link := range newLinks {
			_ = link.Close()
		}
		return fmt.Errorf("failed to inject the prog %d/%d", failedProbes, len(probes))
	}
	*links = append(*links, newLinks...)
	return nil
}

var libSSLCandidates = []string{
	"/lib/x86_64-linux-gnu/libssl.so.1.1", // Ubuntu/Debian
	"/lib/x86_64-linux-gnu/libssl.so.3",   // Newer Ubuntu/Debian
	"/lib64/libssl.so.1.1",                // CentOS/RHEL
	"/lib64/libssl.so.3",                  // Fedora or newer CentOS/RHEL
	"/usr/local/lib/libssl.so",            // Custom builds
}

var libSDirs = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/usr/local/lib",
	"/usr/local/lib64",
}

func findLibSSLPath() (string, error) {
	for _, path := range libSSLCandidates {
		if ok, err := tool.IsFilePath(path); err == nil && ok {
			return path, nil
		}
	}

	for _, dir := range libSDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "libssl.so*"))
		if len(matches) > 0 {
			log.Info().Str("path", matches[0]).Msg("found potential libssl, consider add this to the env")
			for _, path := range matches {
				if ok, err := tool.IsFilePath(path); err == nil && ok {
					return path, nil
				}
			}
		}
	}
	return "", fmt.Errorf("libssl not found, please set the path via args `--ssl-path`")
}

func addSSLProbe(sslPath *string, links *[]link.Link) (*sslObjects, error) {
	attachPaths := []string{}
	libPaths, err := findLibSSLPath()
	if err != nil {
		log.Warn().Err(err).Msg("cannot find the libssl path from the common paths")
	} else {
		attachPaths = append(attachPaths, libPaths)
	}

	if sslPath != nil && len(*sslPath) > 0 {
		if ok, err := tool.IsFilePath(*sslPath); err != nil || !ok {
			return nil, fmt.Errorf("invalid SSL file path: %w", err)
		}
		attachPaths = append(attachPaths, *sslPath)
	}
	if len(attachPaths) == 0 {
		log.Warn().Msg("no valid libssl path to attach")
	}
	log.Info().Any("default_path", attachPaths).Msg("using libssl")

	sslObjs := sslObjects{}
	SSLSpec, err := ebpf.LoadCollectionSpec(sslSpecPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	if err := SSLSpec.LoadAndAssign(&sslObjs, nil); err != nil {
		return nil, fmt.Errorf("failed to load and assign eBPF objects: %w", err)
	}

	var final error
	for _, p := range attachPaths {
		exec, err := link.OpenExecutable(p)
		if err != nil {
			final = errors.Join(final, fmt.Errorf("failed to open OpenSSL file %s: %w", p, err))
		}
		if err = attachSSLProbes(exec, &sslObjs, p, links); err != nil {
			final = errors.Join(final, fmt.Errorf("failed to inject OpenSSL probes to %s: %w", p, err))
		}
		log.Info().Str("path", p).Msg("attaching SSL uprobes")
	}

	return &sslObjs, final
}

type OpenSSLProbe struct {
	links         []link.Link
	obj           *sslObjects
	rb            *ringbuf.Reader
	mu            sync.Mutex
	dynamicProbes map[container.LibKey]string
	libDetector   *container.ContainerLibsDetector
}

func NewOpenSSLProbe(sslPath *string, scanHostProc bool) (*OpenSSLProbe, error) {
	links := []link.Link{}
	obj, err := addSSLProbe(sslPath, &links)
	if obj == nil {
		return nil, fmt.Errorf("failed to create OpenSSL probe: %w", err)
	}
	// continuous as long as some probes work
	if err != nil {
		log.Warn().Err(err).Msg("some errors occurred while attaching OpenSSL probes")
	}
	rb, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return nil, fmt.Errorf("failed to open OpenSSL ringbuf reader: %w", err)
	}
	return &OpenSSLProbe{
		links:         links,
		obj:           obj,
		rb:            rb,
		dynamicProbes: make(map[container.LibKey]string),
		libDetector:   container.NewContainerLibsDetector(scanHostProc),
	}, nil
}

func (op *OpenSSLProbe) Start(ctx context.Context) {
	channel := make(chan container.ContainerOpenSSL, MAX_DYNAMIC_CHANNEL_SIZE)
	go op.libDetector.Start(ctx, channel)
	for containerLibs := range channel {
		for key, path := range containerLibs.Libs {
			op.mu.Lock()
			if _, ok := op.dynamicProbes[key]; ok {
				continue
			}
			exec, err := link.OpenExecutable(path)
			if err != nil {
				log.Error().Err(err).Str("path", path).Any("key", key).Msg("failed to open the SSL lib")
			}
			if err = attachSSLProbes(exec, op.obj, path, &op.links); err != nil {
				log.Error().Err(err).Str("path", path).Any("key", key).Msg("failed to attach SSL probes to the lib")
			}
			log.Info().Str("path", path).Any("key", key).Msg("attaching dynamic SSL uprobes")
			op.dynamicProbes[key] = path
			op.mu.Unlock()
		}
	}
}

func (op *OpenSSLProbe) ReadBuffer() (ringbuf.Record, error) {
	return op.rb.Read()
}

func (op *OpenSSLProbe) Close() error {
	var final error
	if err := op.obj.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close OpenSSL eBPF objects: %w", err))
	}
	if err := op.rb.Close(); err != nil {
		final = errors.Join(final, fmt.Errorf("failed to close OpenSSL ringbuf reader: %w", err))
	}
	op.mu.Lock()
	for i, l := range op.links {
		if err := l.Close(); err != nil {
			final = errors.Join(final, fmt.Errorf("failed to close %d-OpenSSL link: %w", i, err))
		}
	}
	op.mu.Unlock()
	return final
}
