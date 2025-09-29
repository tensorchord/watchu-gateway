package main

import (
	"context"
	"io"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/phuslu/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/tensorchord/watchu"
)

const (
	TETRAGON_SOCKET = "unix:///var/run/tetragon/tetragon.sock"
)

func main() {
	watchu.SetUpLogger()

	conn, err := grpc.NewClient(TETRAGON_SOCKET, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal().Str("path", TETRAGON_SOCKET).Err(err).Msg("failed to dial")
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close the socket connection")
		}
	}()
	client := tetragon.NewFineGuidanceSensorsClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		eventStream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			log.Error().Err(err).Msg("GetEvents failed")
			if st, ok := status.FromError(err); ok {
				if st.Code() == codes.Unavailable {
					log.Info().Msg("service is unavailable, exit")
					os.Exit(0)
				}
			}
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
			}
		}
	}
}
