package ingress

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	buildersyncv1 "github.com/TrueOpen/nexus/gen/buildersync/v1"
	"github.com/TrueOpen/nexus/gen/buildersync/v1/buildersyncv1connect"
	"github.com/TrueOpen/nexus/internal/buildersync"
)

// builderSyncReadMaxBytes bounds one sync batch: a run of items and output frames.
const builderSyncReadMaxBytes = 8 << 20

// BuilderSync applies the sync batches the dispatching Builders of this Builder's groups send
// (buildersync.Receiver).
type BuilderSync interface {
	Sync(ctx context.Context, req *buildersyncv1.SyncRequest) (*buildersyncv1.SyncResponse, error)
}

// WithBuilderSync serves BuilderSyncService on the ingress port. Its requests are authenticated
// by the sender's signature on each batch, so the SDK API key and IP allowlist do not apply.
func WithBuilderSync(sync BuilderSync) Option {
	return func(s *Server) { s.builderSync = sync }
}

// builderSyncService is the Connect handler of BuilderSyncService.
type builderSyncService struct {
	sync BuilderSync
}

var _ buildersyncv1connect.BuilderSyncServiceHandler = builderSyncService{}

// Sync applies one batch.
func (b builderSyncService) Sync(ctx context.Context, req *connect.Request[buildersyncv1.SyncRequest]) (*connect.Response[buildersyncv1.SyncResponse], error) {
	resp, err := b.sync.Sync(ctx, req.Msg)
	if err != nil {
		return nil, mapBuilderSyncErr(err)
	}
	return connect.NewResponse(resp), nil
}

func mapBuilderSyncErr(err error) error {
	switch {
	case errors.Is(err, buildersync.ErrMalformed):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, buildersync.ErrUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, buildersync.ErrNotGroupMember):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, buildersync.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
