package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Submitter is the submission seam for the task-lifecycle on-chain Txs: it encodes, signs and
// broadcasts the typed Tx assembled by nexus. It is an interface in order to:
//   - isolate Tx wrapping/signing (the orchestration state machine does not care about chain encoding);
//   - let the orchestration state machine use a fake submitter for deterministic unit tests.
//
// A successful submit only means "broadcast", not state progress -- truth still comes from chain events (Detailed Design §3 core rule).
// The method set mirrors the Task Msg surface of Keeper Interface Contract §9.4:
//   - SubmitAssign          -> MsgSubmitWorkerHandraises (§4.2.1/§10.1)
//   - SubmitOpenVerify      -> MsgSubmitInferReceipt (§10.3)
//   - SubmitVerifierHandraises -> MsgSubmitVerifierHandraises (§4.2.1/§10.4)
//   - SubmitVerifyCommit    -> MsgBatchSubmitVerifyCommit (§10.6, one per batch)
//   - SubmitVerifyResult    -> MsgBatchSubmitVerifyResult (§10.9, one per batch)
//   - SubmitSettle          -> MsgSettleTask (§10.10a)
//   - SubmitSweepDeadline   -> MsgSweepDeadline (§9.6a/§10.14)
//
// There is no Worker reveal method: §9.4 registers no such Msg and §10.11 keeps
// Worker metric evidence off chain.
//
// MsgSubmitVerifyResult relay is enabled: NATS VERIFY_RESULT now carries the complete frozen
// ResultReceiptV2 signed by the Verifier (including service_authorization_nonce / expiry_height /
// MetricSummaryV1), so it is forwarded verbatim -- the old reason for "intentionally not enabled this round"
// (Nexus could not obtain those fields) went away with the bus migration. MsgSubmitVerifyCommit / MsgSubmitFullResultReveal
// are still not enabled: the Cortex contract has not given them a NATS payload yet.
// MsgReportDataUnavailable must not be relayed per the contract (see the chaincli/txbuild.go comment).
type Submitter interface {
	SubmitAssign(ctx context.Context, tx chaincli.AssignTx) (ProposalResult, error)
	SubmitOpenVerify(ctx context.Context, tx chaincli.OpenVerifyTx) (chaincli.TxResult, error)
	SubmitVerifierHandraises(ctx context.Context, tx chaincli.OpenVerifyTx) (ProposalResult, error)
	SubmitVerifyCommit(ctx context.Context, tx chaincli.VerifyCommitTx) (chaincli.TxResult, error)
	SubmitVerifyResult(ctx context.Context, tx chaincli.VerifyResultTx) (chaincli.TxResult, error)
	SubmitSettle(ctx context.Context, tx chaincli.SettleTx) (chaincli.TxResult, error)
	SubmitSweepDeadline(ctx context.Context, tx chaincli.SweepDeadlineTx) (chaincli.TxResult, error)
}

// BuilderSubmitter covers the two transactions Builder identity maintenance sends. In Phase 0 BuilderBond is fixed
// at zero and creates no bonded stake record (Staking and Slashing Protocol §Phase 0); wire v0.4.1 has no Builder
// bond / unbond messages, so neither does this interface.
type BuilderSubmitter interface {
	SubmitRegisterBuilder(ctx context.Context, tx chaincli.RegisterBuilderTx) (chaincli.TxResult, error)
	SubmitUpdateServiceDescriptor(ctx context.Context, tx chaincli.UpdateServiceDescriptorTx) (chaincli.TxResult, error)
}

type SubmissionPhase string

const (
	SubmissionPrepare   SubmissionPhase = "prepare"
	SubmissionBroadcast SubmissionPhase = "broadcast"
)

// SubmissionError tells financial workflows whether a transaction reached the
// broadcast boundary and whether the node returned a definitive result.
type SubmissionError struct {
	Phase      SubmissionPhase
	Definitive bool
	Result     chaincli.TxResult
	Err        error
}

func (e *SubmissionError) Error() string { return e.Err.Error() }
func (e *SubmissionError) Unwrap() error { return e.Err }

// defaultSubmitter: proto Msg -> Any -> query account_number/sequence ->
// SIGN_MODE_DIRECT signature (chaincli.BuildSignedTx) -> BroadcastTx.
//
// With signer == nil it fails closed: no account sequence query, no broadcast of an unsigned Tx.
type defaultSubmitter struct {
	log           *slog.Logger
	chain         chaincli.Client // source of truth for transactions and Task queries
	hub           chaincli.Client // source of truth for Builder selection and Profile
	signer        chaincli.TxSigner
	serviceSigner signer.Signer
	chainCfg      config.ChainConfig

	// Local sequence cache (Detailed Design §6.1): avoids querying the account per Tx and sequence races under concurrent submits.
	// seqMu serializes signed submissions (the sequence of one account is inherently a serial resource).
	seqMu    sync.Mutex
	accNum   uint64
	sequence uint64
	seqValid bool // false = refresh from chain before the next submit

	simulate simulateCounters
}

// newDefaultSubmitter is the unsigned skeleton submitter (default of coordinator.New).
func newDefaultSubmitter(log *slog.Logger, chain chaincli.Client) Submitter {
	return &defaultSubmitter{log: log, chain: chain}
}

// NewSignedSubmitter is the submitter with real signing (injected at app wiring).
func NewSignedSubmitter(log *slog.Logger, taskChain, hubChain chaincli.Client, accountSigner chaincli.TxSigner, serviceSigner signer.Signer, chainCfg config.ChainConfig) Submitter {
	return &defaultSubmitter{log: log, chain: taskChain, hub: hubChain, signer: accountSigner, serviceSigner: serviceSigner, chainCfg: chainCfg}
}

// NewBuilderSubmitter constructs the Builder register/unbond submitter.
func NewBuilderSubmitter(log *slog.Logger, chain chaincli.Client, s chaincli.TxSigner, chainCfg config.ChainConfig) BuilderSubmitter {
	return &defaultSubmitter{log: log, chain: chain, hub: chain, signer: s, chainCfg: chainCfg}
}

// SubmitAssign relays a Worker-duty handraise proposal as
// MsgSubmitWorkerHandraises (Keeper Interface Contract §4.2.1/§10.1).
//
// Only the scope oneof, the Cortex-signed handraises and submitter_address reach
// the chain. Builder rank, selection proof, candidate set hash, min-handraise
// threshold, reserved fee and infer deadline are Keeper-derived and are refused
// as request copies; the proposal also carries no detached Builder signature,
// because the Cosmos Tx signer already authorises it.
func (s *defaultSubmitter) SubmitAssign(ctx context.Context, tx chaincli.AssignTx) (ProposalResult, error) {
	if s.signer == nil {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: account signer is required")
	}
	if tx.Submitter == "" || tx.Submitter != s.signer.Address() {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: submitter_address must be the Cosmos signer")
	}
	msg := &taskv1.MsgSubmitWorkerHandraises{SubmitterAddress: tx.Submitter}
	// scopeTaskHash is the authoritative candidate identity this proposal binds to; the two scope branches source it
	// differently: the signed_order branch computes it from the user-signed TaskOrderV2, the existing_task branch
	// uses the on-chain accepted_task_hash. It must then be byte-for-byte equal to every hand-raise.
	var scopeTaskHash []byte
	switch {
	case tx.SignedOrder != nil && tx.ExistingTask != nil:
		return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: scope must be exactly one of signed_order or existing_task")
	case tx.SignedOrder != nil:
		if err := validateSignedOrder(tx.SignedOrder); err != nil {
			return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: %v", err)
		}
		digest, err := nodecontract.TaskOrderHashV2(tx.SignedOrder.GetOrder())
		if err != nil {
			return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: %v", err)
		}
		scopeTaskHash = digest[:]
		msg.Scope = &taskv1.WorkerHandraiseScopeV1{Scope: &taskv1.WorkerHandraiseScopeV1_SignedOrder{SignedOrder: tx.SignedOrder}}
	case tx.ExistingTask != nil:
		if len(tx.ExistingTask.GetTaskId()) != hash32Len || len(tx.ExistingTask.GetTaskHash()) != hash32Len {
			return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: existing_task requires canonical task_id and task_hash")
		}
		scopeTaskHash = tx.ExistingTask.GetTaskHash()
		msg.Scope = &taskv1.WorkerHandraiseScopeV1{Scope: &taskv1.WorkerHandraiseScopeV1_ExistingTask{ExistingTask: tx.ExistingTask}}
	default:
		return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: scope must be exactly one of signed_order or existing_task")
	}
	if err := validateWorkerHandraises(tx.WorkerHandraises); err != nil {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: %v", err)
	}
	if err := validateScopeTaskHash(scopeTaskHash, tx.WorkerHandraises); err != nil {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitWorkerHandraises: %v", err)
	}
	operators := make([]string, len(tx.WorkerHandraises))
	for i, hr := range tx.WorkerHandraises {
		operators[i] = hr.GetMember().GetOperatorAddress()
	}
	return s.submitHandraiseProposal(ctx, handraiseProposal{
		kind: "MsgSubmitWorkerHandraises", typeURL: chaincli.TypeURLMsgSubmitWorkerHandraises, operators: operators,
		build: func(keep []int) proto.Message {
			subset := proto.Clone(msg).(*taskv1.MsgSubmitWorkerHandraises)
			subset.Handraises = make([]*taskv1.WorkerHandraiseV1, 0, len(keep))
			for _, i := range keep {
				subset.Handraises = append(subset.Handraises, tx.WorkerHandraises[i])
			}
			return subset
		},
	})
}

// SubmitOpenVerify relays the Worker-signed receipt as MsgSubmitInferReceipt
// (Keeper Interface Contract §10.3). The Verifier window, legal set, selected Verifier set
// and every deadline are derived by the Keeper in the same transaction, so the
// old MsgOpenVerify request copies (selected verifiers, window proof, builder
// rank/proof, work unit, token count) are gone.
func (s *defaultSubmitter) SubmitOpenVerify(ctx context.Context, tx chaincli.OpenVerifyTx) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSubmitInferReceipt: account signer is required")
	}
	if tx.Submitter == "" || tx.Submitter != s.signer.Address() {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSubmitInferReceipt: submitter_address must be the Cosmos signer")
	}
	if err := validateInferReceipt(tx.InferReceipt); err != nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSubmitInferReceipt: %v", err)
	}
	return s.submitMsg(ctx, "MsgSubmitInferReceipt", chaincli.TypeURLMsgSubmitInferReceipt, &taskv1.MsgSubmitInferReceipt{
		Receipt:          tx.InferReceipt,
		SubmitterAddress: tx.Submitter,
	})
}

// SubmitVerifierHandraises relays a Verifier-duty handraise proposal as
// MsgSubmitVerifierHandraises (Keeper Interface Contract §4.2.1/§10.4).
//
// It is a separate stage on purpose: §4.4 only opens the Builder proposal window
// at `h_window`, after the InferReceipt transaction froze the eligibility source
// and the whole clock. Submitting handraises inside the receipt transaction would
// be rejected as out-of-window.
func (s *defaultSubmitter) SubmitVerifierHandraises(ctx context.Context, tx chaincli.OpenVerifyTx) (ProposalResult, error) {
	if s.signer == nil {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitVerifierHandraises: account signer is required")
	}
	if tx.Submitter == "" || tx.Submitter != s.signer.Address() {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitVerifierHandraises: submitter_address must be the Cosmos signer")
	}
	taskID, err := nodecontract.Hash32Bytes("task_id", tx.TaskID)
	if err != nil {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitVerifierHandraises: %v", err)
	}
	if err := validateVerifierHandraises(tx.VerifierHandraises, taskID); err != nil {
		return ProposalResult{}, prepareSubmissionError("MsgSubmitVerifierHandraises: %v", err)
	}
	operators := make([]string, len(tx.VerifierHandraises))
	for i, hr := range tx.VerifierHandraises {
		operators[i] = hr.GetMember().GetOperatorAddress()
	}
	return s.submitHandraiseProposal(ctx, handraiseProposal{
		kind: "MsgSubmitVerifierHandraises", typeURL: chaincli.TypeURLMsgSubmitVerifierHandraises, operators: operators,
		build: func(keep []int) proto.Message {
			subset := &taskv1.MsgSubmitVerifierHandraises{TaskId: taskID, SubmitterAddress: tx.Submitter,
				Handraises: make([]*taskv1.VerifierHandraiseV1, 0, len(keep))}
			for _, i := range keep {
				subset.Handraises = append(subset.Handraises, tx.VerifierHandraises[i])
			}
			return subset
		},
	})
}

// SubmitVerifyResult relays a Verifier-signed result receipt as
// MsgSubmitVerifyResult (Keeper Interface Contract §10.9). Receipt bytes are passed through verbatim.
// SubmitVerifyCommit relays one Verifier-signed VerifyCommitV1 via MsgBatchSubmitVerifyCommit
// (Keeper Interface Contract §10.6).
//
// Why batch: the single MsgSubmitVerifyCommit only accepts the Verifier's own current service address
// as submitter (direct-submission path); Builder relay must go through batch, whose outer signer must be the
// selected Builder's current service address. The initial implementation sends one per message as soon as it arrives, no batching.
func (s *defaultSubmitter) SubmitVerifyCommit(ctx context.Context, tx chaincli.VerifyCommitTx) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgBatchSubmitVerifyCommit: account signer is required")
	}
	if tx.Submitter == "" || tx.Submitter != s.signer.Address() {
		return chaincli.TxResult{}, prepareSubmissionError("MsgBatchSubmitVerifyCommit: submitter_address must be the Cosmos signer")
	}
	if tx.Commit == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgBatchSubmitVerifyCommit: commit is required")
	}
	return s.submitMsg(ctx, "MsgBatchSubmitVerifyCommit", chaincli.TypeURLMsgBatchSubmitVerifyCommit, &taskv1.MsgBatchSubmitVerifyCommit{
		Commits:          []*taskv1.VerifyCommitV1{tx.Commit},
		SubmitterAddress: tx.Submitter,
	})
}

// SubmitVerifyResult relays one Verifier-signed ResultReceiptV2 via MsgBatchSubmitVerifyResult
// (Keeper Interface Contract §10.9). The single MsgSubmitVerifyResult likewise only accepts the Verifier
// itself as submitter; Builder relay must use batch (the single form was previously rejected by the chain).
func (s *defaultSubmitter) SubmitVerifyResult(ctx context.Context, tx chaincli.VerifyResultTx) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgBatchSubmitVerifyResult: account signer is required")
	}
	if tx.Submitter == "" || tx.Submitter != s.signer.Address() {
		return chaincli.TxResult{}, prepareSubmissionError("MsgBatchSubmitVerifyResult: submitter_address must be the Cosmos signer")
	}
	if tx.Receipt == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgBatchSubmitVerifyResult: receipt is required")
	}
	return s.submitMsg(ctx, "MsgBatchSubmitVerifyResult", chaincli.TypeURLMsgBatchSubmitVerifyResult, &taskv1.MsgBatchSubmitVerifyResult{
		Receipts:         []*taskv1.ResultReceiptV2{tx.Receipt},
		SubmitterAddress: tx.Submitter,
	})
}

// SubmitSettle triggers normal settlement as MsgSettleTask
// (Keeper Interface Contract §10.10a). The public request is exactly
// `1=task_id:Hash32,2=submitter_address:Address`: the Keeper derives verdict,
// consensus cluster, receipt refs, evidence root, facts hash, cutoff height,
// challenge close height and the settlement duty Builder from authoritative
// state, and a funded Task still fails closed until the settlement encoding is frozen.
func (s *defaultSubmitter) SubmitSettle(ctx context.Context, tx chaincli.SettleTx) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSettleTask: account signer is required")
	}
	if tx.Submitter == "" || tx.Submitter != s.signer.Address() {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSettleTask: submitter_address must be the Cosmos signer")
	}
	taskID, err := nodecontract.Hash32Bytes("task_id", tx.TaskID)
	if err != nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSettleTask: %v", err)
	}
	return s.submitMsg(ctx, "MsgSettleTask", chaincli.TypeURLMsgSettleTask, &taskv1.MsgSettleTask{
		TaskId:           taskID,
		SubmitterAddress: tx.Submitter,
	})
}

// SubmitSweepDeadline runs one bounded deadline sweep as MsgSweepDeadline
// (Keeper Interface Contract §9.6a/§10.14).
//
// This is not a relay: MsgSweepDeadline is the only public deadline runner in V1; the public runner and
// EndBlock share one internal executor, any account may submit it and pays its own gas, so the Cosmos Tx
// signer is Nexus's own account and no external detached signature is needed.
//
// Only the task branch of §5.9 DeadlineLocatorV1 is exposed. challenge / evidence_request and the four kinds
// EVIDENCE_REQUEST / CHALLENGE_RESOLVE / CHALLENGE_CLOSE / EVIDENCE_CLEANUP are not active yet --
// no ACTIVE writer can create the corresponding objects, so the sweep executor must reject them --
// so we fail closed here rather than broadcast a Tx that is certain to be rejected and burn gas for nothing.
func (s *defaultSubmitter) SubmitSweepDeadline(ctx context.Context, tx chaincli.SweepDeadlineTx) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSweepDeadline: account signer is required")
	}
	if tx.Submitter == "" || tx.Submitter != s.signer.Address() {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSweepDeadline: submitter_address must be the Cosmos signer")
	}
	if err := validateTaskDeadlineKind(tx.DeadlineKind); err != nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSweepDeadline: %v", err)
	}
	taskID, err := nodecontract.Hash32Bytes("task_id", tx.TaskID)
	if err != nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgSweepDeadline: %v", err)
	}
	return s.submitMsg(ctx, "MsgSweepDeadline", chaincli.TypeURLMsgSweepDeadline, &taskv1.MsgSweepDeadline{
		Locator: &taskv1.DeadlineLocatorV1{
			Locator: &taskv1.DeadlineLocatorV1_Task{
				Task: &taskv1.TaskDeadlineLocator{TaskId: taskID, DeadlineKind: tx.DeadlineKind},
			},
		},
		SubmitterAddress: tx.Submitter,
	})
}

// validateTaskDeadlineKind admits only kinds that belong to TaskDeadlineLocator in the §5.9 table and
// are registered in the V1 handler surface.
func validateTaskDeadlineKind(kind taskv1.DeadlineKindV1) error {
	switch kind {
	case taskv1.DeadlineKindV1_DEADLINE_KIND_V1_TASK_FINALITY,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_TASK_SETTLEMENT,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_REVEAL,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_COMMIT,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_OPEN,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_WORKER_INFER,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_WORKER_ASSIGNMENT,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_FINAL:
		return nil
	case taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_ROUND_CLOSE,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_CHALLENGE_WINDOW_CLOSE,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_EVIDENCE_CLEANUP:
		// wire v0.4.1 challenge/evidence kinds: Phase 0 does not activate challenge rounds, Nexus has no
		// corresponding local object to sweep; leave them to the chain's own EndBlock.
		return fmt.Errorf("deadline_kind %s is not swept by the Builder in Phase 0", kind.String())
	case taskv1.DeadlineKindV1_DEADLINE_KIND_V1_SESSION_LIFECYCLE:
		return fmt.Errorf("deadline_kind SESSION_LIFECYCLE belongs to the session_lifecycle locator, not a task locator")
	default:
		return fmt.Errorf("deadline_kind must be a task-scoped kind of §5.9")
	}
}

// hash32Len is the raw consensus length of every Hash32 field (§1.1).
const hash32Len = 32

// signature64Len is the raw length of a compact secp256k1 service signature
// (§1.1). User order signatures are recoverable 65-byte R||S||V instead; see
// nodecontract.ValidateSignedOrderEnvelopeV2.
const signature64Len = 64

// validateScopeTaskHash is the last gate on Task identity before submitting on-chain.
//
// Frozen contract §4.2.1 requires the scope (SignedOrderV2 or ExistingTaskRefV1) and every
// WorkerHandraiseV1.task_hash in this proposal to point at the same order version. The Keeper repeats this
// check (node x/task/keeper/msg_server_worker_handraises.go:62); doing it locally first avoids
// sending a Tx that is doomed to rejection and, more importantly, fails closed in one place for these four cases:
//
//   - a hand-raise carries the wrong candidate hash;
//   - one proposal mixes different hashes;
//   - a hand-raise is bound to a stale RBF version -- an older quote version of the same task_id has a
//     different task_hash and is ruled out by comparison with the current scope;
//   - the envelope's payload digest (or any other 32-byte commitment) is passed off as task_hash --
//     it can never equal the value computed by H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V2", ...).
func validateScopeTaskHash(scopeTaskHash []byte, handraises []*taskv1.WorkerHandraiseV1) error {
	if len(scopeTaskHash) != hash32Len {
		return fmt.Errorf("scope task_hash must be 32 raw bytes")
	}
	for i, handraise := range handraises {
		if !bytes.Equal(handraise.GetTaskHash(), scopeTaskHash) {
			return fmt.Errorf("handraise %d task_hash %x does not match the proposal scope task_hash %x",
				i, handraise.GetTaskHash(), scopeTaskHash)
		}
	}
	return nil
}

func validateSignedOrder(signed *taskv1.SignedOrderV2) error {
	// TaskOrder Hashing and Signing §7.3/§7.5: "eip712" + 65-byte recoverable signature. Same rule as ingress.
	if err := nodecontract.ValidateSignedOrderEnvelopeV2(signed.GetSignatureScheme(), signed.GetUserSignature()); err != nil {
		return err
	}
	order := signed.GetOrder()
	if order == nil {
		return fmt.Errorf("signed_order order is required")
	}
	if order.GetSchemaVersion() == 0 || order.GetChainId() == "" || order.GetUserAddress() == "" ||
		order.GetModelId() == "" || order.GetProfileVersion() == 0 || order.GetBuilderSetId() == "" {
		return fmt.Errorf("signed_order order identity fields are incomplete")
	}
	for field, value := range map[string][]byte{
		"session_id":                order.GetSessionId(),
		"input_hash":                order.GetInputHash(),
		"session_anchor_block_hash": order.GetSessionAnchorBlockHash(),
		"builder_set_hash":          order.GetBuilderSetHash(),
	} {
		if len(value) != hash32Len {
			return fmt.Errorf("signed_order %s must be 32 raw bytes", field)
		}
	}
	if order.GetGenerationParams() == nil || order.GetDeadlinePolicy() == nil {
		return fmt.Errorf("signed_order requires typed generation_params and deadline_policy")
	}
	if order.GetEarliestSubmitHeight() == 0 || order.GetOrderExpireHeight() <= order.GetEarliestSubmitHeight() {
		return fmt.Errorf("signed_order submit window is not a strictly increasing height range")
	}
	return nil
}

// validateWorkerHandraises enforces the caller-side half of §4.2.2: a proposal
// carries at least one handraise, handraises ascend by slot and each slot is
// unique. Membership, eligibility, liability and signature validity stay with
// the Keeper, which reloads the authoritative snapshot.
func validateWorkerHandraises(handraises []*taskv1.WorkerHandraiseV1) error {
	if len(handraises) == 0 {
		return fmt.Errorf("handraises must not be empty")
	}
	previousSlot := -1
	for i, handraise := range handraises {
		if handraise == nil {
			return fmt.Errorf("handraise %d is nil", i)
		}
		if handraise.GetDuty() != sharedv1.Duty_DUTY_WORKER {
			return fmt.Errorf("handraise %d duty must be WORKER", i)
		}
		if handraise.GetSchemaVersion() == 0 || handraise.GetChainId() == "" || handraise.GetModelId() == "" ||
			handraise.GetProfileVersion() == 0 || handraise.GetServiceAuthorizationNonce() == 0 ||
			handraise.GetExpiryHeight() == 0 {
			return fmt.Errorf("handraise %d is incomplete", i)
		}
		if len(handraise.GetTaskId()) != hash32Len || len(handraise.GetTaskHash()) != hash32Len {
			return fmt.Errorf("handraise %d task_id and task_hash must be 32 raw bytes", i)
		}
		if len(handraise.GetServiceSignature()) != signature64Len {
			return fmt.Errorf("handraise %d service_signature must be 64 raw bytes", i)
		}
		slot, err := validateCandidateMember(handraise.GetMember(), i, previousSlot)
		if err != nil {
			return err
		}
		previousSlot = slot
	}
	return nil
}

func validateVerifierHandraises(handraises []*taskv1.VerifierHandraiseV1, taskID []byte) error {
	if len(handraises) == 0 {
		return fmt.Errorf("handraises must not be empty")
	}
	previousSlot := -1
	for i, handraise := range handraises {
		if handraise == nil {
			return fmt.Errorf("handraise %d is nil", i)
		}
		if handraise.GetDuty() != sharedv1.Duty_DUTY_VERIFIER {
			return fmt.Errorf("handraise %d duty must be VERIFIER", i)
		}
		if handraise.GetSchemaVersion() == 0 || handraise.GetChainId() == "" || handraise.GetModelId() == "" ||
			handraise.GetProfileVersion() == 0 || handraise.GetServiceAuthorizationNonce() == 0 ||
			handraise.GetExpiryHeight() == 0 {
			return fmt.Errorf("handraise %d is incomplete", i)
		}
		if !bytes.Equal(handraise.GetTaskId(), taskID) {
			return fmt.Errorf("handraise %d task_id does not match the request locator", i)
		}
		if len(handraise.GetInferReceiptHash()) != hash32Len || len(handraise.GetOutputHash()) != hash32Len {
			return fmt.Errorf("handraise %d infer_receipt_hash and output_hash must be 32 raw bytes", i)
		}
		if len(handraise.GetServiceSignature()) != signature64Len {
			return fmt.Errorf("handraise %d service_signature must be 64 raw bytes", i)
		}
		slot, err := validateCandidateMember(handraise.GetMember(), i, previousSlot)
		if err != nil {
			return err
		}
		previousSlot = slot
	}
	return nil
}

func validateCandidateMember(member *taskv1.CandidateMemberRefV1, index, previousSlot int) (int, error) {
	if member == nil {
		return 0, fmt.Errorf("handraise %d member is required", index)
	}
	if len(member.GetCandidatePoolSnapshotId()) != hash32Len {
		return 0, fmt.Errorf("handraise %d candidate_pool_snapshot_id must be 32 raw bytes", index)
	}
	if member.GetSlotVersion() == 0 || member.GetOperatorAddress() == "" {
		return 0, fmt.Errorf("handraise %d slot binding is incomplete", index)
	}
	slot := int(member.GetSlot())
	if slot <= previousSlot {
		return 0, fmt.Errorf("handraises must ascend by slot with unique slots")
	}
	return slot, nil
}

// validateInferReceipt enforces the caller-side structure of §5.14: the receipt
// is Worker-signed, carries the ordered required evidence commitments and never
// carries a caller-asserted receipt hash, evidence commitments hash or
// work-unit field (the latter stays blocked until the settlement encoding is frozen).
func validateInferReceipt(receipt *taskv1.InferReceiptV2) error {
	if receipt == nil {
		return fmt.Errorf("receipt is required")
	}
	if receipt.GetSchemaVersion() == 0 || receipt.GetChainId() == "" ||
		receipt.GetWorkerOperatorAddress() == "" || receipt.GetServiceAuthorizationNonce() == 0 ||
		receipt.GetOutputSizeBytes() == 0 || receipt.GetExpiryHeight() == 0 {
		return fmt.Errorf("receipt is incomplete")
	}
	for field, value := range map[string][]byte{
		"task_id":                  receipt.GetTaskId(),
		"task_hash":                receipt.GetTaskHash(),
		"generation_params_digest": receipt.GetGenerationParamsDigest(),
		"output_hash":              receipt.GetOutputHash(),
	} {
		if len(value) != hash32Len {
			return fmt.Errorf("receipt %s must be 32 raw bytes", field)
		}
	}
	if len(receipt.GetServiceSignature()) != signature64Len {
		return fmt.Errorf("receipt service_signature must be 64 raw bytes")
	}
	commitments := receipt.GetRequiredEvidenceCommitments()
	if len(commitments) == 0 {
		return fmt.Errorf("receipt required_evidence_commitments must not be empty")
	}
	previousKind := sharedv1.EvidenceKind_EVIDENCE_KIND_UNSPECIFIED
	for i, commitment := range commitments {
		if commitment == nil {
			return fmt.Errorf("receipt evidence commitment %d is nil", i)
		}
		if commitment.GetEvidenceKind() <= previousKind {
			return fmt.Errorf("receipt evidence commitments must ascend by evidence_kind with unique kinds")
		}
		if len(commitment.GetEvidenceHashOrRoot()) != hash32Len {
			return fmt.Errorf("receipt evidence commitment %d hash must be 32 raw bytes", i)
		}
		previousKind = commitment.GetEvidenceKind()
	}
	return nil
}

func prepareSubmissionError(format string, args ...any) error {
	return &SubmissionError{
		Phase: SubmissionPrepare, Definitive: true,
		Err: fmt.Errorf(format, args...),
	}
}

// SubmitRegisterBuilder submits MsgRegisterBuilder (§9.6a).
//
// wire has only (service_pubkey, service_key_proof, descriptor, builder_operator_address):
// builder_status / descriptor_version / bond / term are all Keeper-derived, and the descriptor is
// the endpoints list itself -- descriptor URI + hash commitment were removed by the frozen contract.
func (s *defaultSubmitter) SubmitRegisterBuilder(ctx context.Context, tx chaincli.RegisterBuilderTx) (chaincli.TxResult, error) {
	if tx.Builder == "" {
		return chaincli.TxResult{}, fmt.Errorf("RegisterBuilderTx: empty builder")
	}
	if tx.ServicePubKey == "" || tx.ServiceKeyProof == "" || tx.AuthorizationNonce == 0 {
		return chaincli.TxResult{}, fmt.Errorf("RegisterBuilderTx: incomplete service key proof-of-possession")
	}
	pubKey, err := hex.DecodeString(tx.ServicePubKey)
	if err != nil || len(pubKey) != 33 || hex.EncodeToString(pubKey) != tx.ServicePubKey {
		return chaincli.TxResult{}, prepareSubmissionError(
			"MsgRegisterBuilder: service_pubkey must be canonical lowercase 66-hex compressed secp256k1")
	}
	proof, err := nodecontract.Signature64Bytes("RegisterBuilderTx service_key_proof", tx.ServiceKeyProof)
	if err != nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterBuilder: %v", err)
	}
	descriptor, err := serviceDescriptorMessage(tx.Endpoints)
	if err != nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterBuilder: %v", err)
	}
	return s.submitMsg(ctx, "MsgRegisterBuilder", chaincli.TypeURLMsgRegisterBuilder, &hubv1.MsgRegisterBuilder{
		ServicePubkey:          pubKey,
		ServiceKeyProof:        proof,
		Descriptor_:            descriptor,
		BuilderOperatorAddress: tx.Builder,
	})
}

// serviceDescriptorMessage normalizes nexus-side endpoints into the §9.6b submission shape:
// ascending by (endpoint_kind, uri bytes), unique kind, URI/protocol_version field-by-field compliant.
// Normalization failures are always definitive, since retrying would only produce the same Keeper-rejected message.
func serviceDescriptorMessage(endpoints []chaincli.ServiceEndpoint) (*hubv1.ServiceDescriptorV1, error) {
	canonical, err := nodecontract.CanonicalServiceEndpoints(endpoints, nodecontract.DefaultServiceEndpointLimits())
	if err != nil {
		return nil, err
	}
	wire := make([]*hubv1.ServiceEndpointV1, len(canonical))
	for i, endpoint := range canonical {
		wire[i] = &hubv1.ServiceEndpointV1{
			EndpointKind:    endpoint.Kind,
			Uri:             endpoint.URI,
			ProtocolVersion: endpoint.ProtocolVersion,
		}
		if endpoint.TLSPubKeyHash != "" {
			// optional field: set only when the config really provides a fingerprint; absent and present-empty
			// are two different encodings in §1.2.
			raw, err := nodecontract.Hash32Bytes("service endpoint tls_pubkey_hash", endpoint.TLSPubKeyHash)
			if err != nil {
				return nil, err
			}
			wire[i].TlsPubkeyHash = raw
		}
	}
	return &hubv1.ServiceDescriptorV1{Endpoints: wire}, nil
}

// SubmitUpdateServiceDescriptor submits MsgUpdateServiceDescriptor (§9.6a).
//
// expected_descriptor_version is the **current** on-chain version: the Keeper asserts equality, writes current+1
// and recomputes descriptor_hash itself. Hence no hash, no activation/expiry heights and no
// controller_signature here -- authorization is the Cosmos account signature of this Tx.
func (s *defaultSubmitter) SubmitUpdateServiceDescriptor(ctx context.Context, tx chaincli.UpdateServiceDescriptorTx) (chaincli.TxResult, error) {
	if tx.OperatorAddress == "" || tx.ParticipantType == "" {
		return chaincli.TxResult{}, fmt.Errorf("UpdateServiceDescriptorTx: incomplete participant identity")
	}
	if tx.ExpectedDescriptorVersion == 0 {
		return chaincli.TxResult{}, fmt.Errorf("UpdateServiceDescriptorTx: expected_descriptor_version must be the current on-chain version")
	}
	participantType, ok := sharedv1.ParticipantType_value["PARTICIPANT_TYPE_"+tx.ParticipantType]
	if !ok || sharedv1.ParticipantType(participantType) == sharedv1.ParticipantType_PARTICIPANT_TYPE_UNSPECIFIED {
		return chaincli.TxResult{}, prepareSubmissionError(
			"MsgUpdateServiceDescriptor: participant type %q is not a hub.v1.ParticipantType value", tx.ParticipantType)
	}
	descriptor, err := serviceDescriptorMessage(tx.Endpoints)
	if err != nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgUpdateServiceDescriptor: %v", err)
	}
	return s.submitMsg(ctx, "MsgUpdateServiceDescriptor", chaincli.TypeURLMsgUpdateServiceDescriptor, &hubv1.MsgUpdateServiceDescriptor{
		ParticipantType:           sharedv1.ParticipantType(participantType),
		ExpectedDescriptorVersion: tx.ExpectedDescriptorVersion,
		Descriptor_:               descriptor,
		OperatorAddress:           tx.OperatorAddress,
	})
}

// atomicAmount converts a local uint64 amount into the public chain wire shared.v1.Amount
// (decimal atomic_units string, see shared/v1/amount.proto).
func atomicAmount(units uint64) *sharedv1.Amount {
	return &sharedv1.Amount{AtomicUnits: strconv.FormatUint(units, 10)}
}

func (s *defaultSubmitter) submitterAddress() string {
	if s.signer != nil {
		return s.signer.Address()
	}
	return ""
}

// submitMsg is the unified wrap + sign + broadcast path.
func (s *defaultSubmitter) submitMsg(ctx context.Context, kind, typeURL string, msg proto.Message) (chaincli.TxResult, error) {
	msgAny, err := chaincli.PackAny(typeURL, msg)
	if err != nil {
		return chaincli.TxResult{}, &SubmissionError{Phase: SubmissionPrepare, Definitive: true, Err: err}
	}

	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("submit %s: account signer is required", kind)
	}

	// sequence cache (Detailed Design §6.1): serial submits per account; increment on success,
	// refresh and retry once on sequence mismatch, mark dirty on network uncertainty for the next refresh.
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return s.submitAnyLocked(ctx, kind, typeURL, msgAny)
}

// submitLocked is submitMsg for a caller that already holds seqMu.
func (s *defaultSubmitter) submitLocked(ctx context.Context, kind, typeURL string, msg proto.Message) (chaincli.TxResult, error) {
	msgAny, err := chaincli.PackAny(typeURL, msg)
	if err != nil {
		return chaincli.TxResult{}, &SubmissionError{Phase: SubmissionPrepare, Definitive: true, Err: err}
	}
	return s.submitAnyLocked(ctx, kind, typeURL, msgAny)
}

func (s *defaultSubmitter) submitAnyLocked(ctx context.Context, kind, typeURL string, msgAny *anypb.Any) (chaincli.TxResult, error) {
	if !s.seqValid {
		if err := s.refreshSequence(ctx); err != nil {
			return chaincli.TxResult{}, &SubmissionError{Phase: SubmissionPrepare, Err: fmt.Errorf("submit %s: account info: %w", kind, err)}
		}
	}

	res, err := s.signAndBroadcast(ctx, kind, typeURL, msgAny)
	if err != nil {
		// Broadcast failure (network/node unreachable): unknown whether the sequence was consumed -> mark dirty.
		s.seqValid = false
		return res, err
	}
	if res.Code == 0 {
		s.sequence++ // CheckTx passed: sequence consumed
		s.logBroadcastAccepted(kind, typeURL, res)
		return res, nil
	}
	if !isSequenceMismatch(res) {
		// Other CheckTx rejections (incl. idempotent rejection because this stage was already submitted by someone else):
		// sequence not consumed, cache still valid. Must be raised as error -- the caller (state machine) only looks at
		// err to decide whether to reset the per-stage dedup flag; returning silently would make it think the broadcast succeeded and wait forever for a chain event.
		return res, definitiveSubmissionError(kind, res, "rejected by CheckTx")
	}

	// Sequence mismatch (e.g. an external tool sent a Tx from the same account): refresh -> re-sign -> rebroadcast once.
	s.log.Warn("tx rejected: sequence mismatch, refreshing and retrying once",
		"kind", kind, "stale_sequence", s.sequence, "raw_log", res.RawLog)
	if err := s.refreshSequence(ctx); err != nil {
		return res, &SubmissionError{Phase: SubmissionPrepare, Result: res, Err: fmt.Errorf("submit %s: refresh sequence: %w", kind, err)}
	}
	res, err = s.signAndBroadcast(ctx, kind, typeURL, msgAny)
	if err != nil {
		s.seqValid = false
		return res, err
	}
	if res.Code != 0 {
		return res, definitiveSubmissionError(kind, res, "rejected after sequence refresh")
	}
	s.sequence++
	s.logBroadcastAccepted(kind, typeURL, res)
	return res, nil
}

// logBroadcastAccepted records "this Tx passed CheckTx" along with its tx_hash.
//
// It is the single success exit for all on-chain Txs -- both success paths of submitMsg (first attempt and
// after a sequence-mismatch retry) go through it, so all nine Msgs are covered without logging in every Submit*.
//
// tx_hash is the starting point for troubleshooting: CheckTx code=0 only means it entered the mempool; the
// DeliverTx outcome is only known by QueryTx with this hash (which is exactly what the coordinator's periodic
// reconciliation does). Previously the success path logged nothing, so operators only saw the
// "rejected by DeliverTx" line on failure and had no hash to look the Tx up on-chain themselves.
//
// Level Info: at most nine Txs per Task, bounded by task count, so it does not flood; and during
// integration "did this Tx actually go out" is the most frequently asked question.
func (s *defaultSubmitter) logBroadcastAccepted(kind, typeURL string, res chaincli.TxResult) {
	if s.log == nil {
		return
	}
	s.log.Info("tx broadcast accepted by CheckTx",
		"kind", kind,
		"type_url", typeURL,
		"tx_hash", hex.EncodeToString(res.TxHash),
		"code", res.Code,
		"height", res.Height,
		"signer", s.signer.Address(),
		"sequence", s.sequence-1, // already incremented above; report the one actually used
	)
}

// refreshSequence queries the account from the chain and resets the local cache. Caller must hold seqMu.
func (s *defaultSubmitter) refreshSequence(ctx context.Context) error {
	acc, err := s.chain.AccountInfo(ctx, s.signer.Address())
	if err != nil {
		s.seqValid = false
		return err
	}
	s.accNum = acc.AccountNumber
	s.sequence = acc.Sequence
	s.seqValid = true
	return nil
}

// txParams are the signing parameters with the currently cached sequence. Caller must hold seqMu.
func (s *defaultSubmitter) txParams() chaincli.TxParams {
	return chaincli.TxParams{
		ChainID:       s.chainCfg.ChainID,
		AccountNumber: s.accNum,
		Sequence:      s.sequence,
		GasLimit:      s.chainCfg.GasLimit,
		FeeDenom:      s.chainCfg.FeeDenom,
		FeeAmount:     s.chainCfg.FeeAmount,
	}
}

// signAndBroadcast signs with the currently cached sequence and broadcasts. Caller must hold seqMu.
func (s *defaultSubmitter) signAndBroadcast(ctx context.Context, kind, typeURL string, msgAny *anypb.Any) (chaincli.TxResult, error) {
	raw, err := chaincli.BuildSignedTx(s.signer, s.txParams(), msgAny)
	if err != nil {
		return chaincli.TxResult{}, &SubmissionError{Phase: SubmissionPrepare, Definitive: true, Err: fmt.Errorf("submit %s: %w", kind, err)}
	}
	s.log.Debug("submit tx signed", "kind", kind, "type_url", typeURL,
		"signer", s.signer.Address(), "sequence", s.sequence, "bytes", len(raw))
	res, err := s.chain.BroadcastTx(ctx, raw)
	if err != nil {
		return res, &SubmissionError{Phase: SubmissionBroadcast, Result: res, Err: fmt.Errorf("submit %s: broadcast: %w", kind, err)}
	}
	return res, nil
}

func definitiveSubmissionError(kind string, res chaincli.TxResult, reason string) error {
	return &SubmissionError{
		Phase:      SubmissionBroadcast,
		Definitive: true,
		Result:     res,
		Err:        fmt.Errorf("submit %s: %s (code %d): %s", kind, reason, res.Code, res.RawLog),
	}
}

// isSequenceMismatch detects cosmos-sdk's sequence mismatch rejection (sdkerrors.ErrWrongSequence code=32).
func isSequenceMismatch(res chaincli.TxResult) bool {
	return res.Code == 32 || strings.Contains(res.RawLog, "account sequence mismatch")
}
