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
	"github.com/phuslu/log"
	"github.com/tidwall/gjson"

	"github.com/tensorchord/watchu/collector"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 stdio stdio.bpf.c -- -I../headers

const (
	STDIO_READ  = 4
	STDIO_WRITE = 2
)

type MCPRequest struct {
	JsonRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      int            `json:"id"`
}

type MCPResponse struct {
	JsonRPC string         `json:"jsonrpc"`
	Result  map[string]any `json:"result"`
	ID      int            `json:"id"`
}

func isValidMCPMessage(event *stdioEvent) bool {
	if !gjson.GetBytes(event.Data[:event.DataLen], "jsonrpc").Exists() {
		return false
	}
	switch event.Rw {
	case STDIO_READ:
		return gjson.GetBytes(event.Data[:event.DataLen], "method").Exists()
	case STDIO_WRITE:
		return gjson.GetBytes(event.Data[:event.DataLen], "result").Exists()
	default:
		log.Error().Uint8("rw", event.Rw).Msg("unknown RW type")
		return false
	}
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
		log.Fatal().Int("failed", failedProbes).Msg("failed to attach stdio")
	}
}

type StdioProbe struct {
	rb      *ringbuf.Reader
	objs    *stdioObjects
	links   []link.Link
	client  *collector.GatewayClient
	channel chan *collector.RawStdIO
}

func NewStdioProbe(client *collector.GatewayClient) *StdioProbe {
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
		rb:      rb,
		objs:    &objs,
		links:   links,
		client:  client,
		channel: make(chan *collector.RawStdIO, collector.GatewayChannelSize),
	}
}

func (sp *StdioProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for stdio events...")
	go sp.client.IngestStdIOEvent(ctx, sp.channel)

	var event stdioEvent
	for {
		record, err := sp.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("stdio ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("read from ringbuffer error")
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("parsing stdio ringbuf record")
			continue
		}

		if !isValidMCPMessage(&event) {
			continue
		}

		sp.channel <- &collector.RawStdIO{
			ElapsedNs: event.TimestampNs,
			PidTid:    event.PidTgid,
			UidGid:    event.UidGid,
			Rw:        event.Rw,
			Data:      bytes.Clone(event.Data[:event.DataLen]),
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
				Str("comm", collector.CharsToString(event.Comm[:])).
				Bytes("data", event.Data[:event.DataLen]).
				Msg("stdio event")
		}
	}
}

func (sp *StdioProbe) Close() {
	err := sp.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close stdio objects")
	}
	close(sp.channel)
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
