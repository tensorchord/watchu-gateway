package execve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/phuslu/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/tensorchord/watchu/collector"
)

type TetragonClient struct {
	conn          *grpc.ClientConn
	client        tetragon.FineGuidanceSensorsClient
	gatewayClient *collector.GatewayClient
}

func unixSocketPath(target string) (string, bool) {
	if strings.HasPrefix(target, "unix://") {
		p := strings.TrimPrefix(target, "unix://")
		return p, strings.HasPrefix(p, "/")
	}
	if strings.HasPrefix(target, "/") {
		return target, true
	}
	return "", false
}

func waitForUnixSocket(ctx context.Context, path string) error {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()

	for {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("unix socket not ready: %s: %w", path, ctx.Err())
		case <-t.C:
		}
	}
}

func dialTetragon(ctx context.Context, target string) (*grpc.ClientConn, error) {
	if p, ok := unixSocketPath(target); ok {
		if err := waitForUnixSocket(ctx, p); err != nil {
			return nil, err
		}
		return grpc.DialContext(
			ctx,
			"passthrough:///"+p,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", addr)
			}),
			grpc.WithBlock(),
			grpc.WithReturnConnectionError(),
		)
	}

	return grpc.DialContext(
		ctx,
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	)
}

func NewTetragonClient(ctx context.Context, socketPath string, gatewayClient *collector.GatewayClient) (*TetragonClient, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	conn, err := dialTetragon(dialCtx, socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to tetragon: %w", err)
	}
	log.Info().Str("target", socketPath).Msg("connected to Tetragon gRPC server")
	client := tetragon.NewFineGuidanceSensorsClient(conn)
	return &TetragonClient{
		conn:          conn,
		client:        client,
		gatewayClient: gatewayClient,
	}, nil
}

func (tc *TetragonClient) Close() {
	err := tc.conn.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close the socket connection")
	}
}

func (tc *TetragonClient) Run(ctx context.Context, out chan<- *collector.RawExec) error {
	for {
		eventStream, err := tc.client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			log.Error().Err(err).Msg("GetEvents failed")
			if st, ok := status.FromError(err); ok {
				if st.Code() == codes.Unavailable {
					return err
				}
				if st.Code() == codes.Canceled {
					return nil
				}
			}
			log.Error().Err(err).Msg("failed to get event from Tetragon, retry the next event after 1 seconds")
			time.Sleep(time.Second)
			continue
		}
		for {
			event, err := eventStream.Recv()
			if errors.Is(err, io.EOF) {
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
				out <- &collector.RawExec{
					Timestamp: exec.Process.StartTime.AsTime(),
					Pid:       exec.Process.Pid.Value,
					PPid:      ppid,
					ExecId:    exec.Process.ExecId,
					PExecId:   exec.Process.ParentExecId,
					Cwd:       exec.Process.Cwd,
					Comm:      exec.Process.Binary,
					Args:      exec.Process.Arguments,
					Docker:    exec.Process.Docker,
				}
			}
		}
	}
}

func RunTetragonWithRetry(ctx context.Context, socketPath string, gatewayClient *collector.GatewayClient) {
	channel := make(chan *collector.RawExec, collector.GatewayChannelSize)
	go gatewayClient.IngestExecEvent(ctx, channel)

	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tc, err := NewTetragonClient(ctx, socketPath, gatewayClient)
		if err != nil {
			log.Warn().Err(err).Str("socket", socketPath).Msg("tetragon not ready, retrying")
			time.Sleep(backoff)
			continue
		}

		err = tc.Run(ctx, channel)
		tc.Close()
		if err == nil || errors.Is(err, context.Canceled) {
			return
		}

		log.Warn().Err(err).Msg("tetragon stream ended, reconnecting")
		time.Sleep(backoff)
	}
}
