package coordinator

import "time"

// Orchestration parameters (Detailed Design §8 parameter table; happy-path values are fixed, the rest are placeholder defaults).
const (
	// proposalHandraiseMin is the minimum number of valid hand-raises one proposal must carry.
	//
	// Interface & Topic Catalogue §5.5: "a single proposal only needs to contain at least 1 legal, non-duplicate
	// Worker handraise; whether the candidate count needed for Worker assignment is reached is evaluated only at
	// window close against the accumulated union bitmap." §13.3 acceptance scenarios 2 and 6 (same rule on the
	// Verifier side) restate this.
	//
	// Sufficiency is decided by the Keeper over the **union of all Task Builder proposals**, not by a single
	// Builder over the few it received. Hard-coding 3 here moved the chain's decision locally with a narrower
	// input: with three Builders each receiving 1 different hand-raise the union of 3 is fully sufficient,
	// yet none of the three would submit and the task simply timed out.
	proposalHandraiseMin = 1

	// selectedVerifierCount is the pick count for the local legacy selected-verifier CSV;
	// it and proposalHandraiseMin are two different quantities -- do not share one constant again.
	//
	// The authoritative source is the Task's locked selected_verifier_count (§5.9), not this literal;
	// the CSV is not submitted on-chain either (SubmitOpenVerify only takes InferReceipt and Submitter). It is kept
	// only because OpenVerifyTx still carries this historical field.
	selectedVerifierCount = 3

	// verifierProposalBatchDelay: how long to accumulate after the first Verifier hand-raise before submitting a proposal.
	// Hand-raises usually arrive within a few hundred milliseconds; submitting one by one becomes several
	// MsgSubmitVerifierHandraises (three per order in the test environment, same block). Submit immediately once
	// selectedVerifierCount are collected, otherwise wait this window; later arrivals go in a follow-up Tx.
	verifierProposalBatchDelay = 2 * time.Second

	// minConsistentVerifyResults is the settlement precondition: minimum number of matching copies of the same
	// sampled value (>= 2 matching V_i on-chain suffice to construct the consensus value).
	minConsistentVerifyResults = 2

	// credentialTTL is the maximum single validity period of a retrieval credential (renewable by refresh).
	credentialTTL = time.Hour

	// challengeGasEstimate is the placeholder gas estimate for PrepareChallenge (switch to real estimation once Simulate is wired).
	challengeGasEstimate = 200_000
)
