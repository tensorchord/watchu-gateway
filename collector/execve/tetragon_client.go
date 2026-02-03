package execve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/phuslu/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/tensorchord/watchu/collector"
)

const (
	MAX_RETRY_COUNT        = 8
	DEFAULT_SLEEP_DURATION = time.Second
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
	for health == nil && retry < MAX_RETRY_COUNT {
		health, errHealth = client.GetHealth(ctx, &tetragon.GetHealthStatusRequest{})
		if errHealth == nil {
			break
		}
		log.Error().Err(errHealth).Msg("failed to get the health status of the tetragon")
		health = nil
		retry++
		if err := sleepWithContext(ctx, DEFAULT_SLEEP_DURATION*time.Duration(retry)); err != nil {
			// context canceled, exit
			break
		}
	}
	if health == nil {
		log.Error().Err(errHealth).Int("retry", MAX_RETRY_COUNT).Msg("failed to wait for the tetragon service to become available")
		return false
	}
	log.Info().Str("status", health.String()).Msg("tetragon service is available")
	return true
}

func connectWithRetry(path string, ctx context.Context) (*grpc.ClientConn, error) {
	retry := 0
	var conn *grpc.ClientConn
	var errDial error
	for conn == nil && retry < MAX_RETRY_COUNT {
		conn, errDial = grpc.NewClient(path, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if errDial == nil {
			break
		}
		log.Error().Err(errDial).Msg("failed to dial tetragon gRPC server")
		conn = nil
		retry++
		if err := sleepWithContext(ctx, DEFAULT_SLEEP_DURATION*time.Duration(retry)); err != nil {
			// context canceled, exit
			break
		}
	}
	if conn == nil {
		return nil, fmt.Errorf("failed to connect to tetragon gRPC server after %d retries: %w", MAX_RETRY_COUNT, errDial)
	}
	return conn, nil
}

type TetragonClient struct {
	conn          *grpc.ClientConn
	client        tetragon.FineGuidanceSensorsClient
	gatewayClient *collector.GatewayClient
	channel       chan *collector.RawExec

	// Process tree tracking for correlation_id filtering
	// Maps exec_id -> correlation_id (inherited from parent or self)
	correlationMap map[string]string
	correlationMu  sync.RWMutex

	// Enable filtering mode: only send events related to skill security
	filterEnabled bool
}

func NewTetragonClient(path string, gatewayClient *collector.GatewayClient, ctx context.Context) (*TetragonClient, error) {
	return NewTetragonClientWithFilter(path, gatewayClient, ctx, true)
}

func NewTetragonClientWithFilter(path string, gatewayClient *collector.GatewayClient, ctx context.Context, filterEnabled bool) (*TetragonClient, error) {
	conn, err := connectWithRetry(path, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	client := tetragon.NewFineGuidanceSensorsClient(conn)

	if !isServiceAvailable(client, ctx) {
		return nil, fmt.Errorf("failed to get the health status of the tetragon")
	}
	state := conn.GetState()
	log.Info().Str("state", state.String()).Bool("filter_enabled", filterEnabled).Msg("connected to Tetragon gRPC server")

	return &TetragonClient{
		conn:           conn,
		client:         client,
		gatewayClient:  gatewayClient,
		channel:        make(chan *collector.RawExec, collector.GatewayChannelSize),
		correlationMap: make(map[string]string),
		filterEnabled:  filterEnabled,
	}, nil
}


// extractCorrelationID extracts WATCHU_CORRELATION_ID from environment variables
func extractCorrelationID(envVars []*tetragon.EnvVar) string {
	for _, envVar := range envVars {
		if envVar != nil && envVar.Key == "WATCHU_CORRELATION_ID" {
			return envVar.Value
		}
	}
	return ""
}

// getOrInheritCorrelationID returns the correlation_id for a process.
// If the process has its own WATCHU_CORRELATION_ID, use it.
// Otherwise, inherit from parent if tracked.
func (tc *TetragonClient) getOrInheritCorrelationID(execID, parentExecID, selfCorrelationID string) string {
	// If process has its own correlation_id, use it
	if selfCorrelationID != "" {
		tc.correlationMu.Lock()
		tc.correlationMap[execID] = selfCorrelationID
		tc.correlationMu.Unlock()
		return selfCorrelationID
	}

	// Try to inherit from parent
	tc.correlationMu.RLock()
	parentCorrelation := tc.correlationMap[parentExecID]
	tc.correlationMu.RUnlock()

	if parentCorrelation != "" {
		tc.correlationMu.Lock()
		tc.correlationMap[execID] = parentCorrelation
		tc.correlationMu.Unlock()
		return parentCorrelation
	}

	return ""
}

// cleanupCorrelationMap periodically cleans up old entries to prevent memory leaks
func (tc *TetragonClient) cleanupCorrelationMap() {
	// Simple cleanup: if map grows too large, clear oldest entries
	// In production, consider using an LRU cache with TTL
	tc.correlationMu.Lock()
	defer tc.correlationMu.Unlock()

	const maxEntries = 100000
	if len(tc.correlationMap) > maxEntries {
		// Clear half of the entries (simple strategy)
		count := 0
		for k := range tc.correlationMap {
			if count >= maxEntries/2 {
				break
			}
			delete(tc.correlationMap, k)
			count++
		}
		log.Info().Int("remaining", len(tc.correlationMap)).Msg("cleaned up correlation map")
	}
}

func (tc *TetragonClient) Close() {
	close(tc.channel)
	err := tc.conn.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close the socket connection")
	}
}

func (tc *TetragonClient) Start(ctx context.Context) {
	go tc.gatewayClient.IngestExecEvent(ctx, tc.channel)
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
				execID := exec.Process.ExecId
				parentExecID := exec.Process.ParentExecId
				selfCorrelationID := extractCorrelationID(exec.Process.EnvironmentVariables)

				// Get or inherit correlation_id from parent
				correlationID := tc.getOrInheritCorrelationID(execID, parentExecID, selfCorrelationID)

				// Filter mode: skip events without correlation_id
				if tc.filterEnabled && correlationID == "" {
					// Not related to skill security, skip
					continue
				}

				log.Debug().
					Str("exec_id", execID).
					Str("p_exec_id", parentExecID).
					Str("comm", exec.Process.Binary).
					Str("correlation_id", correlationID).
					Str("event", "exec").
					Msg("exec event")

				pp := exec.Parent
				var ppid uint32
				if pp != nil && pp.Pid != nil {
					ppid = pp.Pid.Value
				}
				tc.channel <- &collector.RawExec{
					Timestamp:     exec.Process.StartTime.AsTime(),
					Pid:           exec.Process.Pid.Value,
					PPid:          ppid,
					ExecId:        execID,
					PExecId:       parentExecID,
					Cwd:           exec.Process.Cwd,
					Comm:          exec.Process.Binary,
					Args:          exec.Process.Arguments,
					Docker:        exec.Process.Docker,
					CorrelationID: correlationID,
				}

				// Periodically cleanup correlation map
				tc.cleanupCorrelationMap()
			}
		}
	}
}
