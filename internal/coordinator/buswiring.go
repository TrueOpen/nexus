// Production wiring of the bus envelope (TRUEOPEN_BUS_ENVELOPE_V2).
//
// busadapter only provides the envelope assembly/verification mechanism; the local facts -- which private key
// signs, where the current service key is looked up, which kv holds replay and outbox -- are injected here.
// Publisher/Receiver are one per Coordinator and shared by all taskFSMs: the replay store must be shared across
// tasks, otherwise the same frame could be replayed under another task (same semantics as the old busEnvelopes, gh #37).
package coordinator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/busadapter"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

const (
	// busEnvelopeTTLMS is expires_at_unix_ms - issued_at_unix_ms.
	// The contract defines it as a deployment config shared by Nexus/Cortex, not a governance parameter.
	busEnvelopeTTLMS = 30_000

	// busReplaySafetyMarginMS is how long a replay tombstone is kept beyond expires_at.
	busReplaySafetyMarginMS = 300_000

	// busEnvelopeMaxBytes is the early rejection bound before decoding, taken from the bus protocol constant:
	// bus.Verify checks it itself; this local check only saves the decode and digest. NATS default
	// max_payload is also 1 MiB; control-plane messages are several orders of magnitude below it.
	busEnvelopeMaxBytes = bus.MaxEnvelopeBytes

	// busRepublishInterval is the outbox republish period. The envelope TTL is only 30 seconds; relying on restart
	// republish alone means runtime publish failures are silently dropped. Periodic republish retries failed entries
	// a few times within TTL and prunes expired entries as a side effect (Pending), keeping NSBusOutbox bounded.
	busRepublishInterval = 10 * time.Second

	// busReplayPruneInterval is the replay store prune period. StoreOnce treats expired tombstones only as
	// "key released" and does not delete them; without pruning NSBusReplay only grows.
	busReplayPruneInterval = 10 * time.Minute
)

// participantTypeName maps the bus/hubv1 participant enum value to the servicekey query domain string.
// Unknown values return the empty string; callers fail closed.
func participantTypeName(participantType int32) string {
	switch participantType {
	case bus.ParticipantBuilder:
		return servicekey.ParticipantBuilder
	case bus.ParticipantCortex:
		return servicekey.ParticipantCortex
	default:
		return ""
	}
}

// republishOutbox re-sends unexpired outbox envelopes and prunes expired ones. Failures only warn: envelopes
// have a TTL, an expired one is not worth resending, and all bus messages fall back to on-chain state and create no consensus fact.
func (c *Coordinator) republishOutbox(ctx context.Context) {
	if c.busPublisher == nil {
		return
	}
	if err := c.busPublisher.Republish(ctx); err != nil {
		c.log.Warn("bus outbox republish failed", "err", err)
	}
}

// startBusMaintenance starts the bus maintenance loop: periodic outbox republish, low-frequency replay store prune.
// Both partitions (NSBusOutbox / NSBusReplay) are write-only persistent state and grow without bound without this
// loop; republish is also the only retry trigger for runtime publish failures.
func (c *Coordinator) startBusMaintenance() {
	if c.busPublisher == nil {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		republish := time.NewTicker(busRepublishInterval)
		defer republish.Stop()
		prune := time.NewTicker(busReplayPruneInterval)
		defer prune.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-republish.C:
				c.republishOutbox(context.Background())
			case <-prune.C:
				if c.busReplay != nil {
					if err := c.busReplay.Prune(uint64(nowMS())); err != nil {
						c.log.Warn("bus replay store prune failed", "err", err)
					}
				}
			}
		}
	}()
}

// buildBusAdapters assembles the shared Publisher/Receiver. Returns (nil, nil) when no service key is configured:
// when a compliant frame cannot be signed the only correct behavior is not to send; inbound is treated as chain lookup unavailable.
func (c *Coordinator) buildBusAdapters() (*busadapter.Publisher, *busadapter.Receiver) {
	if c.serviceSigner == nil || c.serviceKeys == nil || c.active.self == "" {
		return nil, nil
	}
	publisher := busadapter.NewPublisher(busadapter.PublisherConfig{
		ChainID:         c.chainID,
		OperatorAddress: c.active.self,
		ParticipantType: bus.ParticipantBuilder,
		Signer:          c.serviceSigner,
		AuthorizationNonce: func(ctx context.Context) (uint64, error) {
			return c.selfAuthorizationNonce(ctx)
		},
		Outbox: busadapter.NewOutbox(c.kv),
		Bus:    c.bus,
		TTLMS:  busEnvelopeTTLMS,
		Now:    nowMSU64,
	})
	c.busReplay = busadapter.NewKVReplayStore(c.kv)
	receiver := busadapter.NewReceiver(busadapter.ReceiverConfig{
		ChainID:              c.chainID,
		LookupBinding:        c.lookupServiceBinding,
		Replay:               c.busReplay,
		MaxEnvelopeBytes:     busEnvelopeMaxBytes,
		ReplaySafetyMarginMS: busReplaySafetyMarginMS,
		Now:                  nowMSU64,
	})
	return publisher, receiver
}

// selfAuthorizationNonce reads the authorization nonce of this node's current Builder binding (envelope field 7)
// and asserts along the way that the on-chain public key is this local private key's -- otherwise frames we sign
// can never verify at the peer; failing early beats letting the peer find out for us.
func (c *Coordinator) selfAuthorizationNonce(ctx context.Context) (uint64, error) {
	publicKey, state, err := servicekey.Current(
		ctx, c.serviceKeys, c.addressPrefix, servicekey.ParticipantBuilder, c.active.self)
	if err != nil {
		if errors.Is(err, servicekey.ErrAuthority) {
			return 0, fmt.Errorf("%w: %v", busadapter.ErrAuthorityUnavailable, err)
		}
		return 0, err
	}
	if !equalBytes(publicKey, c.serviceSigner.PubKeyCompressed()) {
		return 0, fmt.Errorf("on-chain service key does not match the local signer")
	}
	if state.AuthorizationNonce == 0 {
		// Both Cortex and Nexus treat 0 as "not read", and the contract does not allow it on the wire.
		return 0, fmt.Errorf("%w: service binding has no authorization nonce", busadapter.ErrAuthorityUnavailable)
	}
	return state.AuthorizationNonce, nil
}

// lookupServiceBinding looks up the inbound sender's current service binding (key lookup of verification step 5).
// Query infrastructure failures are wrapped as ErrAuthorityUnavailable so the JetStream consumer Naks for
// redelivery; an invalid binding is returned as an ordinary error, which wire classifies as ErrKeyBinding.
func (c *Coordinator) lookupServiceBinding(
	ctx context.Context, participantType int32, operator string,
) (bus.KeyBinding, error) {
	name := participantTypeName(participantType)
	if name == "" {
		return bus.KeyBinding{}, fmt.Errorf("unknown participant type %d", participantType)
	}
	publicKey, state, err := servicekey.Current(ctx, c.serviceKeys, c.addressPrefix, name, operator)
	if err != nil {
		if errors.Is(err, servicekey.ErrAuthority) {
			return bus.KeyBinding{}, fmt.Errorf("%w: %v", busadapter.ErrAuthorityUnavailable, err)
		}
		return bus.KeyBinding{}, err
	}
	return bus.KeyBinding{
		PubKeyCompressed:   publicKey,
		AuthorizationNonce: state.AuthorizationNonce,
		Active:             true, // servicekey.Current already asserted status ACTIVE
	}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nowMSU64 is the clock injection point for busadapter.
func nowMSU64() uint64 { return uint64(nowMS()) }
