package ops

// Diagnostics is what the status file shows of the dispatching Builder's state. It carries counts,
// heights, public keys and addresses; never a token, private key, secret URL or payload. Errors
// names the parts that could not be read (their fields stay zero).
type Diagnostics struct {
	BuilderAddress string `json:"builder_address"`
	ChainHeight    uint64 `json:"chain_height"`
	// ServiceAuthorizationNonce and ServicePubKey are this Builder's current BUILDER service
	// binding on chain.
	ServiceAuthorizationNonce uint64 `json:"service_authorization_nonce"`
	ServicePubKey             string `json:"service_pubkey,omitempty"`
	// BuilderSetID is the current BuilderSet snapshot and BuilderSetMembers its size.
	BuilderSetID      string `json:"builder_set_id,omitempty"`
	BuilderSetMembers int    `json:"builder_set_members,omitempty"`
	// VRFEpoch is the epoch at ChainHeight and VRFPubKey the local key the chain registered for it.
	VRFEpoch  uint64 `json:"vrf_epoch"`
	VRFPubKey string `json:"vrf_pubkey,omitempty"`
	// StandingHandraises are the handraises held, RejectRateSuspended the Workers not admitted
	// for their reject rate.
	StandingHandraises  int `json:"standing_handraises"`
	RejectRateSuspended int `json:"reject_rate_suspended"`
	// LatestRoot is the latest signed handraise root (nil before the first).
	LatestRoot *RootDiagnostics `json:"latest_handraise_root,omitempty"`
	// BoundSessions are the followed sessions bound to this Builder.
	BoundSessions int `json:"bound_sessions"`
	// InFlight is the in-flight ledger.
	InFlight InFlightDiagnostics `json:"in_flight"`
	// RecordOutbox is the record outbox: Waiting entries go out with the next block's record.
	RecordOutbox RecordOutboxDiagnostics `json:"record_outbox"`
	Takeovers    int                     `json:"takeovers"`
	// Streams are the Cortex dispatch streams and the downlink messages not acknowledged yet.
	Streams StreamDiagnostics `json:"streams"`
	// BuilderSync is the group sync sender: counts since start and the order/member pairs with
	// unacknowledged items.
	BuilderSync BuilderSyncDiagnostics `json:"builder_sync"`
	// Responses are the compensation rebuttals and challenge answers since start.
	Responses ResponseDiagnostics `json:"responses"`
	Errors    map[string]string   `json:"errors,omitempty"`
}

// RootDiagnostics describes a handraise root.
type RootDiagnostics struct {
	RootHeight  uint64 `json:"root_height"`
	RootVersion uint64 `json:"root_version"`
	Leaves      int    `json:"leaves"`
	Admitted    int    `json:"admitted"`
}

// InFlightDiagnostics counts the in-flight ledger.
type InFlightDiagnostics struct {
	Sessions int `json:"sessions"`
	// Orders still dispatching or accepted and their max_fee sum in atomic units.
	Orders int    `json:"orders"`
	MaxFee string `json:"max_fee"`
	// Recorded orders the session state has not caught up with.
	Recorded int `json:"recorded"`
	// SuspendedSessions stop dispatching after a failed record.
	SuspendedSessions int `json:"suspended_sessions"`
}

// RecordOutboxDiagnostics counts the record outbox.
type RecordOutboxDiagnostics struct {
	Entries      int `json:"entries"`
	Waiting      int `json:"waiting_for_next_record"`
	Takeovers    int `json:"takeover_entries"`
	Transactions int `json:"transactions"`
}

// StreamDiagnostics counts the dispatch streams.
type StreamDiagnostics struct {
	Sessions             int `json:"sessions"`
	Unacked              int `json:"resend_backlog"`
	OperatorsWithBacklog int `json:"operators_with_backlog"`
	RetainedBroadcasts   int `json:"retained_broadcasts"`
}

// BuilderSyncDiagnostics counts the group sync sender.
type BuilderSyncDiagnostics struct {
	Batches     uint64 `json:"batches"`
	Failures    uint64 `json:"failures"`
	RateLimited uint64 `json:"rate_limited"`
	Alarms      uint64 `json:"alarms"`
	Outstanding int    `json:"outstanding"`
}

// ResponseDiagnostics counts the rebuttals and challenge answers.
type ResponseDiagnostics struct {
	ClaimsSeen             uint64 `json:"claims_seen"`
	ClaimsRebutted         uint64 `json:"claims_rebutted"`
	ClaimsOwed             uint64 `json:"claims_owed"`
	ChallengesAnswered     uint64 `json:"challenges_answered"`
	UnanswerableChallenges uint64 `json:"unanswerable_challenges"`
}
