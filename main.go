package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func main() {
	conn, err := grpc.NewClient("unix:///var/run/tetragon/tetragon.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()
	client := tetragon.NewFineGuidanceSensorsClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		eventStream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			slog.Error("GetEvents failed", "error", err)
			if st, ok := status.FromError(err); ok {
				if st.Code() == codes.Unavailable {
					slog.Info("service is unavailable, exit")
					os.Exit(0)
				}
			}
		}
		for {
			event, err := eventStream.Recv()
			if err == io.EOF {
				slog.Info("event stream closed")
				break
			}
			if err != nil {
				slog.Error("event stream Recv failed", "error", err)
				break
			}
			// slog.Info("event received", "node", event.NodeName)

			// kprobe := event.GetProcessKprobe()
			// if kprobe != nil {
			// 	slog.Info("kprobe", "pid", kprobe.Process.Pid, "cmd", kprobe.Process.Binary, "msg", kprobe.Message, "policy", kprobe.PolicyName)
			// }

			uprobe := event.GetProcessUprobe()
			if uprobe != nil {
				slog.Info("uprobe", "pid", uprobe.Process.Pid, "cmd", uprobe.Process.Binary, "policy", uprobe.PolicyName, "msg", uprobe.Message)
				tags := uprobe.GetTags()
				var size int
				if len(tags) > 0 {
					if strings.HasSuffix(tags[0], "ex") {
						size = int(uprobe.Args[1].GetUintArg())
					} else {
						size = int(uprobe.Args[1].GetIntArg())
					}
				}
				slog.Info("arg", "size", size)
				buf := uprobe.Args[0].GetBytesArg()
				if len(buf) > 0 {
					limit := min(size, len(buf))
					slog.Info("body", "buf", string(buf[:limit]))
				}
				truncated := uprobe.Args[0].GetTruncatedBytesArg()
				if truncated != nil && len(truncated.BytesArg) > 0 {
					limit := min(size, len(truncated.BytesArg))
					slog.Info("body", "truncated", string(truncated.BytesArg[:limit]))
				}
			}

			// trace := event.GetProcessTracepoint()
			// if trace != nil {
			// 	slog.Info("tracepoint", "pid", trace.Process.Pid, "cmd", trace.Process.Binary, "msg", trace.Message, "policy", trace.PolicyName)
			// }

			// exec := event.GetProcessExec()
			// if exec != nil {
			// 	slog.Info("exec", "pid", exec.Process.Pid, "cmd", exec.Process.Binary, "args", exec.Process.Arguments)
			// }

			// exit := event.GetProcessExit()
			// if exit != nil {
			// 	slog.Info("exit", "pid", exit.Process.Pid, "cmd", exit.Process.Binary, "status", exit.Status)
			// }
		}
	}
}
