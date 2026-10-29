package dispatcher

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// buildRecord is the unsigned DispatchRecordV1 of an accepted order. The fields the chain compares
// with the winner ticket (reference height, pool snapshot, VRF epoch, output, proof and scheme,
// bound_change_height and the sticky commitments) are copied from that ticket; sticky_applied is
// the order's first-round decision, true even when the promoted Worker did not win. The rounds
// list every attempt in rank order with its outcome, the reject digest of a REJECTED attempt and
// the RTT tier of a TIMEOUT.
func buildRecord(chainID, builder string, st *orderState, winner *taskv1.DispatchTicketV1, winnerHash []byte) (*taskv1.DispatchRecordV1, error) {
	r := &taskv1.DispatchRecordV1{
		SchemaVersion:           schemaVersion,
		ChainId:                 chainID,
		TaskId:                  mustHex(st.TaskID),
		TaskHash:                mustHex(st.TaskHash),
		SessionId:               append([]byte(nil), winner.GetSessionId()...),
		OrderSequence:           st.Sequence,
		BuilderAddress:          builder,
		ReferenceHeight:         winner.GetReferenceHeight(),
		CandidatePoolSnapshotId: append([]byte(nil), winner.GetCandidatePoolSnapshotId()...),
		VrfEpoch:                winner.GetVrfEpoch(),
		VrfOutput:               append([]byte(nil), winner.GetVrfOutput()...),
		VrfProof:                append([]byte(nil), winner.GetVrfProof()...),
		RandomnessScheme:        winner.GetRandomnessScheme(),
		BoundChangeHeight:       winner.GetBoundChangeHeight(),
		StickyAnchorSequence:    winner.GetStickyAnchorSequence(),
		StickyRunCount:          winner.GetStickyRunCount(),
		StickyApplied:           st.StickyApplied,
		DispatchTicketHash:      append([]byte(nil), winnerHash...),
	}
	for _, round := range st.Rounds {
		out := &taskv1.DispatchRoundV1{
			DispatchRound:       round.Number,
			HandraiseRootDigest: append([]byte(nil), round.RootDigest...),
		}
		for i, a := range round.Attempts {
			var ticket taskv1.DispatchTicketV1
			if err := proto.Unmarshal(a.Ticket, &ticket); err != nil {
				return nil, fmt.Errorf("stored ticket of rank %d: %w", a.Rank, err)
			}
			if i == 0 {
				out.RosterHash = append([]byte(nil), ticket.GetRosterHash()...)
			}
			attempt := &taskv1.DispatchAttemptV1{
				DispatchTicketHash:   append([]byte(nil), a.Hash...),
				Rank:                 a.Rank,
				Member:               ticket.GetTarget(),
				Outcome:              a.Outcome,
				RejectDigestOrZero32: make([]byte, 32),
			}
			switch a.Outcome {
			case outcomeRejected:
				attempt.RejectDigestOrZero32 = append([]byte(nil), a.RejectDigest...)
			case outcomeTimeout:
				attempt.TimeoutTierOrZero = a.Tier
			}
			out.Attempts = append(out.Attempts, attempt)
		}
		r.Rounds = append(r.Rounds, out)
	}
	return r, nil
}

// bundle is the dispatch entry of an accepted order from its stored bytes.
func (d *Dispatcher) bundle(st *orderState, deadline uint64) (*Bundle, error) {
	w := st.winner()
	if w == nil || len(st.Accept) == 0 || len(st.Record) == 0 {
		return nil, fmt.Errorf("order has no complete accept")
	}
	entry := &taskv1.DispatchEntryV1{
		SignedOrder:  &taskv1.SignedOrderV2{},
		Record:       &taskv1.DispatchRecordV1{},
		WinnerTicket: &taskv1.DispatchTicketV1{},
		Accept:       &taskv1.DispatchAcceptV1{},
	}
	for _, part := range []struct {
		raw []byte
		msg proto.Message
	}{{st.SignedOrder, entry.SignedOrder}, {st.Record, entry.Record}, {w.Ticket, entry.WinnerTicket}, {st.Accept, entry.Accept}} {
		if err := proto.Unmarshal(part.raw, part.msg); err != nil {
			return nil, fmt.Errorf("stored dispatch entry part: %w", err)
		}
	}
	return &Bundle{SessionID: st.SessionID, Sequence: st.Sequence, TaskID: st.TaskID, Deadline: deadline, Entry: entry}, nil
}

// resultHeader is the signed DispatchResultHeaderV1 of an accepted, not yet recorded order.
func (d *Dispatcher) resultHeader(st *orderState) (*nexusv1.DispatchResultHeaderV1, error) {
	w := st.winner()
	if w == nil {
		return nil, fmt.Errorf("order has no winner")
	}
	h := &nexusv1.DispatchResultHeaderV1{
		TaskId:       mustHex(st.TaskID),
		WinnerTicket: &taskv1.DispatchTicketV1{},
		Accept:       &taskv1.DispatchAcceptV1{},
		RecordStatus: taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_PENDING,
	}
	if err := proto.Unmarshal(w.Ticket, h.WinnerTicket); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(st.Accept, h.Accept); err != nil {
		return nil, err
	}
	if _, _, err := signResultHeader(d.cfg.Signer, h); err != nil {
		return nil, err
	}
	return h, nil
}
