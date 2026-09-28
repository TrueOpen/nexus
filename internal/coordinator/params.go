package coordinator

import "time"

// Orchestration parameters (happy-path values are fixed, the rest are placeholder defaults).
const (
	// proposalHandraiseMin is the minimum number of valid hand-raises one proposal must carry.
	//
	// A single proposal only needs to contain at least 1 legal, non-duplicate Worker handraise; whether the
	// candidate count needed for Worker assignment is reached is evaluated only at window close against the
	// accumulated union bitmap. The same rule applies on the Verifier side.
	//
	// Sufficiency is decided by the Keeper over the **union of all Task Builder proposals**, not by a single
	// Builder over the few it received. Hard-coding 3 here moved the chain's decision locally with a narrower
	// input: with three Builders each receiving 1 different hand-raise the union of 3 is fully sufficient,
	// yet none of the three would submit and the task simply timed out.
	proposalHandraiseMin = 1

	// selectedVerifierCount is the pick count for the local legacy selected-verifier CSV;
	// it and proposalHandraiseMin are two different quantities -- do not share one constant again.
	//
	// The authoritative source is the Task's locked selected_verifier_count, not this literal;
	// the CSV is not submitted on-chain either (SubmitOpenVerify only takes InferReceipt and Submitter). It is kept
	// only because OpenVerifyTx still carries this historical field.
	selectedVerifierCount = 3

	// verifierProposalBatchDelay: how long to accumulate after the first Verifier hand-raise before submitting a proposal.
	// Hand-raises usually arrive within a few hundred milliseconds; submitting one by one becomes several
	// MsgSubmitVerifierHandraises (three per order in the test environment, same block). Submit immediately once
	// selectedVerifierCount are collected, otherwise wait this window; later arrivals go in a follow-up Tx.
	verifierProposalBatchDelay = 2 * time.Second

	// credentialTTL is the maximum single validity period of a retrieval credential (renewable by refresh).
	credentialTTL = time.Hour

	// challengeGasEstimate is the placeholder gas estimate for PrepareChallenge (switch to real estimation once Simulate is wired).
	challengeGasEstimate = 200_000
)
