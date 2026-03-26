package execve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/phuslu/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/tensorchord/watchu/collector/export"
)

const (
	maxRetryCount        = 8
	defaultSleepDuration = time.Second
)

func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func isServiceAvailable(client tetragon.FineGuidanceSensorsClient, ctx context.Context) bool {
	retry := 0
	var health *tetragon.GetHealthStatusResponse
	var errHealth error
	for health == nil && retry < maxRetryCount {
		health, errHealth = client.GetHealth(ctx, &tetragon.GetHealthStatusRequest{})
		if errHealth == nil {
			break
		}
		log.Error().Err(errHealth).Msg("failed to get the health status of the tetragon")
		health = nil
		retry++
		if err := sleepWithContext(ctx, defaultSleepDuration*time.Duration(retry)); err != nil {
			// context canceled, exit
			break
		}
	}
	if health == nil {
		log.Error().Err(errHealth).Int("retry", maxRetryCount).Msg("failed to wait for the tetragon service to become available")
		return false
	}
	log.Info().Str("status", health.String()).Msg("tetragon service is available")
	return true
}

func connectWithRetry(path string, ctx context.Context) (*grpc.ClientConn, error) {
	retry := 0
	var conn *grpc.ClientConn
	var errDial error
	for conn == nil && retry < maxRetryCount {
		conn, errDial = grpc.NewClient(path, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if errDial == nil {
			break
		}
		log.Error().Err(errDial).Msg("failed to dial tetragon gRPC server")
		conn = nil
		retry++
		if err := sleepWithContext(ctx, defaultSleepDuration*time.Duration(retry)); err != nil {
			// context canceled, exit
			break
		}
	}
	if conn == nil {
		return nil, fmt.Errorf("failed to connect to tetragon gRPC server after %d retries: %w", maxRetryCount, errDial)
	}
	return conn, nil
}

type TetragonClient struct {
	conn     *grpc.ClientConn
	client   tetragon.FineGuidanceSensorsClient
	exporter *export.Exporter
}

func NewTetragonClient(path string, exporter *export.Exporter, ctx context.Context) (*TetragonClient, error) {
	conn, err := connectWithRetry(path, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	client := tetragon.NewFineGuidanceSensorsClient(conn)

	if !isServiceAvailable(client, ctx) {
		return nil, fmt.Errorf("failed to get the health status of the tetragon")
	}
	state := conn.GetState()
	log.Info().Str("state", state.String()).Msg("connected to Tetragon gRPC server")

	return &TetragonClient{
		conn:     conn,
		client:   client,
		exporter: exporter,
	}, nil
}

func (tc *TetragonClient) Close() {
	err := tc.conn.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close the socket connection")
	}
}

func (tc *TetragonClient) Start(ctx context.Context) {
	channel := make(chan *export.RawExec, export.ExportChannelSize)
	go tc.exporter.IngestExecEvent(ctx, channel)
	defer close(channel)
	for {
		eventStream, err := tc.client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			log.Error().Err(err).Msg("GetEvents failed")
			if st, ok := status.FromError(err); ok {
				if st.Code() == codes.Unavailable {
					log.Info().Msg("service is unavailable")
					if isServiceAvailable(tc.client, ctx) {
						continue
					} else {
						return
					}
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
			if errors.Is(err, io.EOF) {
				log.Info().Msg("event stream closed")
				break
			}
			if err != nil {
				log.Error().Err(err).Msg("event stream Recv failed")
				break
			}

			exec := event.GetProcessExec()
			if exec != nil {
				log.Info().Str("exec_id", exec.Process.ExecId).Str("p_exec_id", exec.Process.ParentExecId).Str("comm", exec.Process.Binary).Str("args", exec.Process.Arguments).Str("event", "exec").Msg("")
				pp := exec.Parent
				var ppid uint32
				if pp != nil && pp.Pid != nil {
					ppid = pp.Pid.Value
				}
				channel <- &export.RawExec{
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
