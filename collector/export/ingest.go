package export

import (
	"context"
)

func (gc *GatewayClient) IngestExecEvent(ctx context.Context, channel <-chan *RawExec) {
	gc.IngestEvents(ctx, pathExec, consumeFromChannel(ctx, gc.Host, channel))
}

func (gc *GatewayClient) IngestRequestEvent(ctx context.Context, channel <-chan *RawRequest) {
	gc.IngestEvents(ctx, pathRequest, consumeFromChannel(ctx, gc.Host, channel))
}

func (gc *GatewayClient) IngestResponseEvent(ctx context.Context, channel <-chan *RawResponse) {
	gc.IngestEvents(ctx, pathResponse, consumeFromChannel(ctx, gc.Host, channel))
}

func (gc *GatewayClient) IngestStdIOEvent(ctx context.Context, channel <-chan *RawStdIO) {
	gc.IngestEvents(ctx, pathStdIO, consumeFromChannel(ctx, gc.Host, channel))
}

func (gc *GatewayClient) IngestPostgresEvent(ctx context.Context, channel <-chan *RawPostgres) {
	gc.IngestEvents(ctx, pathPostgres, consumeFromChannel(ctx, gc.Host, channel))
}

func (gc *GatewayClient) IngestAgentEvent(ctx context.Context, channel <-chan *RecordAgentEvent) {
	gc.IngestEvents(ctx, pathAgentEvent, consumeFromChannel(ctx, gc.Host, channel))
}
