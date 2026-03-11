//go:build amd64 && linux

package execve

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 exec exec.bpf.c -- -I../headers

type ProcExecProbe struct {
	rb    *ringbuf.Reader
	objs  *execObjects
	links []link.Link
}

func attachExecProbes(objs execObjects) ([]link.Link, error) {
	probe := struct {
		group string
		name  string
		prog  *ebpf.Program
	}{"sched", "sched_process_exec", objs.TracepointSchedProcessExec}

	tp, err := link.Tracepoint(probe.group, probe.name, probe.prog, nil)
	if err != nil {
		log.Error().Err(err).Str("group", probe.group).Str("name", probe.name).Msg("failed to attach exec tracepoint")
		return nil, err
	}
	return []link.Link{tp}, nil
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
		objs:  objs,
		links: links,
	}
	p.rb, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Error().Err(err).Msg("failed to open ringbuf reader for exec")
		p.Close()
		return nil, err
	}
	return p, nil
}

func (pep *ProcExecProbe) Start(ch chan<- int32) {
	log.Info().Msg("listen to proc exec events...")
	var event execEvent
	for {
		record, err := pep.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("exec ringbuf reader closed")
				return
			}
			log.Warn().Err(err).Msg("failed to read from exec ringbuf")
			continue
		}
		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("parsing exec ringbuf record")
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
		case ch <- event.Pid:
		default:
			log.Warn().Int32("pid", event.Pid).Msg("failed to push to proc exec channel")
		}
	}
}

func (pep *ProcExecProbe) Close() {
	err := pep.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close exec eBPF objects")
	}
	err = pep.rb.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close exec ringbuf reader")
	}
	for i, l := range pep.links {
		if err := l.Close(); err != nil {
			log.Error().Int("index", i).Err(err).Msgf("failed to close exec link")
		}
	}
}
