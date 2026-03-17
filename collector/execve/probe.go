//go:build amd64 && linux

package execve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 exec exec.bpf.c -- -I../headers

const procChannelSize = 4096

type DynLib struct {
	Proc     int32
	Fd       uint64
	Filepath string
}

type ProcExecProbe struct {
	rbProc     *ringbuf.Reader
	rbDynLib   *ringbuf.Reader
	objs       *execObjects
	links      []link.Link
	ProcChan   chan int32
	DynLibChan chan *DynLib
}

func attachExecProbes(objs execObjects) ([]link.Link, error) {
	probes := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"sched", "sched_process_exec", objs.TracepointSchedProcessExec},
		{"syscalls", "sys_enter_openat", objs.TracepointSysEnterOpenat},
		{"syscalls", "sys_enter_openat2", objs.TracepointSysEnterOpenat},
		{"syscalls", "sys_exit_openat", objs.TracepointSysExitOpenat},
		{"syscalls", "sys_exit_openat2", objs.TracepointSysExitOpenat},
		{"syscalls", "sys_enter_close", objs.TracepointSysEnterClose},
		{"syscalls", "sys_enter_mmap", objs.TracepointSysEnterMmap},
	}

	failed := 0
	links := []link.Link{}
	for _, probe := range probes {
		tp, err := link.Tracepoint(probe.group, probe.name, probe.prog, nil)
		if err != nil {
			log.Error().Err(err).Str("group", probe.group).Str("name", probe.name).Msg("failed to attach exec tracepoint")
			failed++
			continue
		}
		links = append(links, tp)
	}
	if failed > 0 {
		for _, link := range links {
			_ = link.Close()
		}
		return nil, fmt.Errorf("failed to attach %d/%d exec tracepoints", failed, len(probes))
	}
	return links, nil
}

func NewProcExecProbe() (*ProcExecProbe, error) {
	objs := &execObjects{}
	if err := loadExecObjects(objs, nil); err != nil {
		log.Error().Err(err).Msg("failed to load eBPF exec spec")
		return nil, err
	}

	links, err := attachExecProbes(*objs)
	if err != nil {
		log.Error().Err(err).Msg("failed to attach exec probes")
		return nil, err
	}

	p := &ProcExecProbe{
		objs:       objs,
		links:      links,
		ProcChan:   make(chan int32, procChannelSize),
		DynLibChan: make(chan *DynLib, procChannelSize),
	}
	p.rbProc, err = ringbuf.NewReader(objs.ProcEvents)
	if err != nil {
		log.Error().Err(err).Msg("failed to open ringbuf reader for exec")
		p.Close()
		return nil, err
	}
	p.rbDynLib, err = ringbuf.NewReader(objs.DynlibEvents)
	if err != nil {
		log.Error().Err(err).Msg("failed to open ringbuf reader for dynamic library load")
		p.Close()
		return nil, err
	}
	return p, nil
}

func (pep *ProcExecProbe) Start(ctx context.Context) {
	log.Info().Msg("listen to proc exec events...")
	var wg sync.WaitGroup

	wg.Go(func() {
		var event execProc
		for {
			record, err := pep.rbProc.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Info().Msg("exec proc ringbuf reader closed")
					return
				}
				log.Warn().Err(err).Msg("failed to read from exec proc ringbuf")
				continue
			}
			if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Error().Err(err).Msg("parsing exec proc ringbuf record")
				continue
			}
			if log.Debug().Enabled() {
				log.Debug().
					Int32("pid", event.Pid).
					Int32("old_pid", event.OldPid).
					Str("comm", tool.CharsToString(event.Comm[:])).
					Str("filepath", tool.CharsToString(event.Filename[:])).
					Msg("proc exec event")
			}
			select {
			case pep.ProcChan <- event.Pid:
			case <-ctx.Done():
				return
			default:
				log.Warn().Int32("pid", event.Pid).Msg("failed to push to proc exec channel")
			}
		}
	})

	wg.Go(func() {
		var event execDynlib
		for {
			record, err := pep.rbDynLib.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Info().Msg("exec dynlib ringbuf reader closed")
					return
				}
				log.Warn().Err(err).Msg("failed to read from exec dynlib ringbuf")
				continue
			}
			if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Error().Err(err).Msg("parsing exec dynlib ringbuf record")
				continue
			}
			if log.Debug().Enabled() {
				log.Debug().
					Uint64("pid_tgid", event.PidTgid).
					Uint64("fd", event.Fd).
					Str("comm", tool.CharsToString(event.Comm[:])).
					Str("libpath", tool.CharsToString(event.Filename[:])).
					Msg("proc load dynamic library event")
			}
			select {
			case pep.DynLibChan <- &DynLib{
				Proc:     int32(event.PidTgid >> 32),
				Fd:       event.Fd,
				Filepath: tool.CharsToString(event.Filename[:]),
			}:
			case <-ctx.Done():
				return
			default:
				log.Warn().Uint64("pid_tgid", event.PidTgid).Msg("failed to push to exec dynlib channel")
			}
		}
	})
	wg.Wait()
}

func (pep *ProcExecProbe) Close() {
	err := pep.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close exec eBPF objects")
	}
	if pep.rbProc != nil {
		err = pep.rbProc.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close exec ringbuf proc reader")
		}
	}
	if pep.rbDynLib != nil {
		err = pep.rbDynLib.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close exec ringbuf dynlib reader")
		}
	}
	for i, l := range pep.links {
		if err := l.Close(); err != nil {
			log.Error().Int("index", i).Err(err).Msgf("failed to close exec link")
		}
	}
	close(pep.ProcChan)
	close(pep.DynLibChan)
}
