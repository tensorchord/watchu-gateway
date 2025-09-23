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
)

const (
	TETRAGON_SOCKET = "unix:///var/run/tetragon/tetragon.sock"
)

func main() {
	if log.IsTerminal(os.Stderr.Fd()) {
		log.DefaultLogger = log.Logger{
			TimeFormat: "15:04:05",
			Caller:     1,
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				QuoteString:    true,
				EndWithMessage: true,
			},
		}
	}

	conn, err := grpc.NewClient(TETRAGON_SOCKET, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal().Str("path", TETRAGON_SOCKET).Err(err).Msg("failed to dial")
	}
	defer conn.Close()
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
				log.Info().Uint32("pid", kprobe.Process.Pid.Value).Str("cmd", kprobe.Process.Binary).Str("policy", kprobe.PolicyName).Msg("kprobe")
			}

			trace := event.GetProcessTracepoint()
			if trace != nil {
				log.Info().Uint32("pid", trace.Process.Pid.Value).Str("cmd", trace.Process.Binary).Str("policy", trace.PolicyName).Msg("tracepoint")
			}

			exec := event.GetProcessExec()
			if exec != nil {
				log.Info().Uint32("pid", exec.Process.Pid.Value).Str("cmd", exec.Process.Binary).Str("args", exec.Process.Arguments).Msg("exec")
			}
		}
	}
}
