//go:build amd64 && linux

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/export"
	"github.com/tensorchord/watchu/collector/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 pg pg.bpf.c -- -I../headers

func attachPostgresProbes(objs pgObjects, links *[]link.Link) {
	probes := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_sendto", objs.TracepointEnterSendto},
		{"syscalls", "sys_enter_close", objs.TracepointEnterClose},
	}

	failed := 0
	for _, probe := range probes {
		tp, err := link.Tracepoint(probe.group, probe.name, probe.prog, nil)
		if err != nil {
			log.Error().Err(err).Str("group", probe.group).Str("name", probe.name).Msg("failed to attach pg probe")
			failed++
			continue
		}
		*links = append(*links, tp)
	}
	if failed > 0 {
		log.Panic().Int("failed_probes", failed).Msg("failed to attach pg")
	}
}

type PostgresProbe struct {
	rb      *ringbuf.Reader
	objs    *pgObjects
	links   []link.Link
	client  *export.GatewayClient
	channel chan *export.RawPostgres
}

func NewPostgresProbe(client *export.GatewayClient) *PostgresProbe {
	objs := pgObjects{}
	err := loadPgObjects(&objs, nil)
	if err != nil {
		log.Panic().Err(err).Msg("failed to load ebpf spec")
	}

	links := []link.Link{}
	attachPostgresProbes(objs, &links)

	p := &PostgresProbe{
		objs:    &objs,
		links:   links,
		client:  client,
		channel: make(chan *export.RawPostgres, export.GatewayChannelSize),
	}
	p.rb, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		p.Close()
		log.Panic().Err(err).Msg("failed to open ringbuf reader for pg")
	}
	return p
}

func (pp *PostgresProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for postgres read socket events...")
	go pp.client.IngestPostgresEvent(ctx, pp.channel)

	var event pgEvent
	for {
		record, err := pp.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("pg ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("failed to read from pg ringbuf")
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("failed to decode pg event")
			continue
		}

		select {
		case pp.channel <- &export.RawPostgres{
			ElapsedNs: event.TimestampNs,
			PidTid:    event.PidTgid,
			UidGid:    event.UidGid,
			CgroupID:  event.CgroupId,
			Comm:      tool.CharsToString(event.Comm[:]),
			Data:      bytes.Clone(event.Data[:event.DataLen]),
			MsgType:   string(event.MsgType),
		}:
		default:
			log.Warn().Msg("pg event channel is full, dropping event")
		}

		if log.Debug().Enabled() {
			log.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("cgroup_id", event.CgroupId).
				Uint64("fd", event.Fd).
				Byte("msg_type", event.MsgType).
				Uint64("req_len", event.ReqLen).
				Uint64("data_len", event.DataLen).
				Str("comm", tool.CharsToString(event.Comm[:])).
				Bytes("data", event.Data[:event.DataLen]).
				Msg("pg read socket event")
		}
	}
}

func (pp *PostgresProbe) Close() {
	err := pp.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close pg objects")
	}
	if pp.rb != nil {
		err = pp.rb.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close pg ringbuf")
		}
	}
	for i, link := range pp.links {
		err = link.Close()
		if err != nil {
			log.Error().Err(err).Int("index", i).Msg("failed to close pg link")
		}
	}
}
