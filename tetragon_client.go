package watchu

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/phuslu/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type TetragonClient struct {
	conn    *grpc.ClientConn
	client  tetragon.FineGuidanceSensorsClient
	storage *Storage
	channel chan *TableExec
}

func NewTetragonClient(socketPath string, storage *Storage) (*TetragonClient, error) {
	conn, err := grpc.NewClient(socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	state := conn.GetState()
	log.Info().Str("state", state.String()).Msg("connected to Tetragon gRPC server")
	client := tetragon.NewFineGuidanceSensorsClient(conn)
	return &TetragonClient{
		conn:    conn,
		client:  client,
		storage: storage,
		channel: make(chan *TableExec, TableChannelSize),
	}, nil
}

func (tc *TetragonClient) Close() {
	close(tc.channel)
	err := tc.conn.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close the socket connection")
	}
}

func (tc *TetragonClient) Run(ctx context.Context) {
	go tc.storage.InsertExecEvent(ctx, tc.channel)
	for {
		eventStream, err := tc.client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			log.Error().Err(err).Msg("GetEvents failed")
			if st, ok := status.FromError(err); ok {
				if st.Code() == codes.Unavailable {
					log.Info().Msg("service is unavailable, exit")
					return
				}
				if st.Code() == codes.Canceled {
					log.Info().Msg("context is canceled, exit")
					return
				}
			}
			log.Error().Err(err).Msg("failed to get event from Tetragon, retry the next event after 1 seconds")
			time.Sleep(time.Second)
			continue
		}
		for {
			event, err := eventStream.Recv()
			if err == io.EOF {
				log.Info().Msg("event stream closed")
				break
			}
			if err != nil {
				log.Error().Err(err).Msg("event stream Recv failed")
				break
			}

			kprobe := event.GetProcessKprobe()
			if kprobe != nil {
				log.Info().Str("exec_id", kprobe.Process.ExecId).Str("p_exec_id", kprobe.Process.ParentExecId).Str("comm", kprobe.Process.Binary).Str("policy", kprobe.PolicyName).Str("event", "kprobe").Msg("")
			}

			trace := event.GetProcessTracepoint()
			if trace != nil {
				log.Info().Str("exec_id", trace.Process.ExecId).Str("p_exec_id", trace.Process.ParentExecId).Str("comm", trace.Process.Binary).Str("policy", trace.PolicyName).Str("event", "tracepoint").Msg("")
			}

			exec := event.GetProcessExec()
			if exec != nil {
				log.Info().Str("exec_id", exec.Process.ExecId).Str("p_exec_id", exec.Process.ParentExecId).Str("comm", exec.Process.Binary).Str("args", exec.Process.Arguments).Str("event", "exec").Msg("")
				pp := exec.Parent
				var ppid uint32
				if pp != nil && pp.Pid != nil {
					ppid = pp.Pid.Value
				}
				tc.channel <- &TableExec{
					Timestamp: exec.Process.StartTime.AsTime(),
					Pid:       exec.Process.Pid.Value,
					PPid:      ppid,
					ExecId:    exec.Process.ExecId,
					PExecId:   exec.Process.ParentExecId,
					Cwd:       exec.Process.Cwd,
					Comm:      exec.Process.Binary,
					Args:      exec.Process.Arguments,
				}
			}
		}
	}
}
