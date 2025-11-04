//go:build amd64 && linux

package stdio

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/phuslu/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 stdio stdio.bpf.c -- -I../headers

func charsToString(arr []int8) string {
	b := make([]byte, len(arr))
	for i, v := range arr {
		b[i] = byte(v)
	}
	return string(bytes.TrimRight(b, "\x00"))
}

func attachStdioProbes(objs stdioObjects, links *[]link.Link) {
	probes := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_read", objs.TracepointEnterRead},
		{"syscalls", "sys_exit_read", objs.TracepointExitRead},
		{"syscalls", "sys_enter_write", objs.TracepointEnterWrite},
	}

	failedProbes := 0
	for _, probe := range probes {
		tp, err := link.Tracepoint(probe.group, probe.name, probe.prog, nil)
		if err != nil {
			log.Error().Err(err).Str("group", probe.group).Str("name", probe.name).Msg("failed to attach tracepoint")
			failedProbes++
			continue
		}
		*links = append(*links, tp)
	}
	if failedProbes > 0 {
		log.Fatal().Msgf("%d probes failed to attach", failedProbes)
	}
}

type StdioProbe struct {
	rb    *ringbuf.Reader
	objs  *stdioObjects
	links []link.Link
}

func NewStdioProbe() *StdioProbe {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	objs := stdioObjects{}
	if err := loadStdioObjects(&objs, nil); err != nil {
		log.Fatal().Err(err).Msg("failed to load ebpf spec")
	}

	links := []link.Link{}
	attachStdioProbes(objs, &links)

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open ringbuf reader")
	}

	return &StdioProbe{
		rb:    rb,
		objs:  &objs,
		links: links,
	}
}

func (sp *StdioProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for stdio events...")

	var event stdioEvent
	for {
		record, err := sp.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("read from ringbuffer error")
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("parsing stdio ringbuf record")
			continue
		}

		if log.Debug().Enabled() {
			log.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("fd", event.Fd).
				Uint64("req_len", event.ReqLen).
				Uint64("data_len", event.DataLen).
				Uint8("rw", event.Rw).
				Str("comm", charsToString(event.Comm[:])).
				Str("data", string(event.Data[:event.DataLen])).
				Msg("stdio event")
		}
	}
}

func (sp *StdioProbe) Close() {
	err := sp.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close stdio objects")
	}
	err = sp.rb.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close stdio ringbuf reader")
	}
	for i, l := range sp.links {
		err = l.Close()
		if err != nil {
			log.Error().Err(err).Int("index", i).Msg("failed to close stdio link")
		}
	}
}
