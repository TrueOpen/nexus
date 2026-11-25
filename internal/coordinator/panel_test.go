package coordinator

import (
	"context"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/types"
)

type fakePanels struct {
	mu    sync.Mutex
	panel chaincli.AnchorPanel
	err   error
	reads int
}

func (p *fakePanels) QueryAnchorPanel(context.Context, string) (chaincli.AnchorPanel, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
	return p.panel, p.err
}

func (p *fakePanels) set(panel chaincli.AnchorPanel, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.panel, p.err = panel, err
}

type fakeWindows struct {
	mu     sync.Mutex
	byRnd  map[uint32]chaincli.VerifierWindow
	rounds []uint32
}

func (w *fakeWindows) QueryVerifierCandidateWindow(_ context.Context, _ string, round uint32) (chaincli.VerifierWindow, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rounds = append(w.rounds, round)
	window, ok := w.byRnd[round]
	if !ok {
		return chaincli.VerifierWindow{}, chaincli.ErrNotFound
	}
	return window, nil
}

// panelFixture is an anchor-only task whose zero-Verifier round 1 the chain has closed.
type panelFixture struct {
	*verifierProposalFixture
	panels  *fakePanels
	windows *fakeWindows
	openVer openVerifyCounter
}

func newPanelFixture(t *testing.T, name string) *panelFixture {
	t.Helper()
	fx := newVerifierProposalFixture(t, name)
	p := &panelFixture{verifierProposalFixture: fx, panels: &fakePanels{}, windows: &fakeWindows{byRnd: map[uint32]chaincli.VerifierWindow{}},
		openVer: openVerifyCounter{link: fx.link}}
	fx.c.panels = p.panels
	fx.c.verifierWindows = p.windows
	p.windows.byRnd[1] = anchorOnlyWindow
	fx.fsm.setVerifierWindow(anchorOnlyWindow)
	fx.setHeight(150)
	fx.chainAcceptsReceipt(t, 150)
	return p
}

// reconcile applies the chain's view of the task: SETTLING with an empty round 1.
func (p *panelFixture) reconcile(height int64) {
	p.setHeight(uint64(height))
	p.c.applyAuthoritativeTask(p.fsm, p.anchorOnlySettling(160), height)
}

func (p *panelFixture) deliverRound(t *testing.T, candidate string, round uint32) {
	t.Helper()
	hr := testVerifierHandraise(p.session, p.task, candidate, p.output, p.receipt)
	hr.VerifyRound = round
	if err := p.c.HandleVerifierHandraise(context.Background(), candidate, hr); err != nil {
		t.Fatalf("HandleVerifierHandraise(%s): %v", candidate, err)
	}
}

func panelWindow(open uint64) chaincli.VerifierWindow {
	return chaincli.VerifierWindow{WindowRandomnessHeight: open + 5, GeneratedHeight: open + 6,
		BuilderProposalCloseHeight: open + 100, HandraiseCloseHeight: open + 130, Ready: true}
}

func collecting(round, kind uint32, prior ...string) chaincli.AnchorPanel {
	return chaincli.AnchorPanel{AuditMode: chaincli.AnchorAuditModePanel, Round: round, Kind: kind, OpenHeight: 170,
		Collecting: true, PriorMembers: prior}
}

// A panel round the chain opened gets OPEN_VERIFY with the panel round as verify round, and the
// hand-raises that name that round are proposed.
func TestPanelRoundCollectsAndProposesHandraises(t *testing.T) {
	p := newPanelFixture(t, "panel-initial")
	p.panels.set(collecting(2, 1), nil)
	p.windows.byRnd[2] = panelWindow(170)
	p.reconcile(180)

	sent := p.link.openVerifies()
	if len(sent) != 1 || sent[0].GetVerifyRound() != 2 || sent[0].GetWorkerOperatorAddress() != p.fsm.winner {
		t.Fatalf("OPEN_VERIFY for the panel round = %+v, want one with verify_round 2", sent)
	}
	p.reconcile(181)
	if n := p.openVer.count(); n != 1 {
		t.Fatalf("OPEN_VERIFY is sent once per round, got %d", n)
	}

	for _, name := range []string{"panel-v1", "panel-v2"} {
		p.deliverRound(t, testOperator(name), 2)
	}
	if n := len(p.proposed()); n != 0 {
		t.Fatalf("two hand-raises wait for a third or for the next reconciliation, got %d proposals", n)
	}
	p.deliverRound(t, testOperator("panel-v3"), 2)
	got := p.proposed()
	if len(got) != 1 || len(got[0].VerifierHandraises) != 3 {
		t.Fatalf("proposals = %d, want one with three hand-raises", len(got))
	}
	for _, hr := range got[0].VerifierHandraises {
		if hr.GetVerifyRound() != 2 {
			t.Fatalf("proposed hand-raise carries verify_round %d, want the panel round 2", hr.GetVerifyRound())
		}
	}
	// A later hand-raise is proposed alone, at the next reconciliation.
	p.deliverRound(t, testOperator("panel-v4"), 2)
	p.reconcile(182)
	got = p.proposed()
	if len(got) != 2 || len(got[1].VerifierHandraises) != 1 {
		t.Fatalf("a proposal carries only new hand-raises, got %d proposals", len(got))
	}
	assertState(t, p.c, p.session, p.task, types.Verifying)
}

// The Worker of the task, members of earlier panels and hand-raises for another round are never
// proposed.
func TestPanelRoundDropsWorkerPriorMembersAndOtherRounds(t *testing.T) {
	p := newPanelFixture(t, "panel-barred")
	prior := testOperator("panel-old")
	p.panels.set(collecting(3, 2, prior), nil)
	p.windows.byRnd[3] = panelWindow(170)
	p.reconcile(180)

	p.deliverRound(t, p.fsm.winner, 3)                 // the Worker
	p.deliverRound(t, prior, 3)                        // sat on round 2
	p.deliverRound(t, testOperator("panel-wrong"), 2)  // an earlier round
	p.deliverRound(t, testOperator("panel-legacy"), 1) // round 1 of an anchor-only task
	p.reconcile(181)
	if n := len(p.proposed()); n != 0 {
		t.Fatalf("barred or misnumbered hand-raises were proposed: %d", n)
	}
	p.deliverRound(t, testOperator("panel-ok"), 3)
	p.reconcile(182)
	got := proposalOperators(t, p.proposed())
	if len(got) != 1 || got[0] != testOperator("panel-ok") {
		t.Fatalf("proposed %v, want only the eligible candidate", got)
	}
}

// The retry and the re-audit are new rounds with new numbers: the old round's messages are retired
// and OPEN_VERIFY goes out again for the new one.
func TestPanelRetryAndReauditAreNewRounds(t *testing.T) {
	p := newPanelFixture(t, "panel-rounds")
	p.panels.set(collecting(2, 1), nil)
	p.windows.byRnd[2] = panelWindow(170)
	p.reconcile(180)
	p.deliverRound(t, testOperator("panel-a"), 2)

	// Round 2 is drawn: nothing more to collect for it.
	p.panels.set(chaincli.AnchorPanel{AuditMode: chaincli.AnchorAuditModePanel, Round: 2, Kind: 1}, nil)
	p.reconcile(200)
	if got := p.link.retiredRounds(); len(got) != 1 {
		t.Fatalf("retired rounds = %v, want round 2 of the task", got)
	}
	p.deliverRound(t, testOperator("panel-late"), 2)
	// A stale read that still shows round 2 collecting must not reopen it.
	p.panels.set(collecting(2, 1), nil)
	p.reconcile(201)
	if n := p.openVer.count(); n != 1 {
		t.Fatalf("a retired round was reopened: %d OPEN_VERIFY", n)
	}

	// The automatic retry is round 3; the re-audit after it round 4.
	for i, round := range []uint32{3, 4} {
		p.panels.set(collecting(round, round-1, testOperator("panel-a")), nil)
		p.windows.byRnd[round] = panelWindow(300 + uint64(i)*100)
		p.reconcile(310 + int64(i)*100)
		sent := p.link.openVerifies()
		if last := sent[len(sent)-1]; len(sent) != 2+i || last.GetVerifyRound() != round {
			t.Fatalf("round %d: %d OPEN_VERIFY, last verify_round %d", round, len(sent), last.GetVerifyRound())
		}
		p.panels.set(chaincli.AnchorPanel{AuditMode: chaincli.AnchorAuditModePanel, Round: round}, nil)
		p.reconcile(350 + int64(i)*100)
	}
}

// A Builder stops proposing once its proposal window of the round has closed.
func TestPanelRoundStopsAtTheProposalClose(t *testing.T) {
	p := newPanelFixture(t, "panel-close")
	p.panels.set(collecting(2, 1), nil)
	p.windows.byRnd[2] = panelWindow(170) // closes for Builders at 270
	p.reconcile(180)
	p.deliverRound(t, testOperator("panel-a"), 2)
	p.reconcile(270) // would execute at 271
	if n := len(p.proposed()); n != 0 {
		t.Fatalf("proposed after the Builder proposal close: %d", n)
	}
}

// Without panel mode nothing changes for an anchor-only task: no OPEN_VERIFY, no proposal.
func TestAnchorOnlyTaskWithoutPanelModeIsUntouched(t *testing.T) {
	for name, panel := range map[string]struct {
		p   chaincli.AnchorPanel
		err error
	}{
		"validator-vote":  {p: chaincli.AnchorPanel{AuditMode: 1}},
		"not-sampled":     {err: chaincli.ErrNotFound},
		"old-chain":       {err: chaincli.ErrAnchorPanelUnsupported},
		"panel-no-round":  {p: chaincli.AnchorPanel{AuditMode: chaincli.AnchorAuditModePanel}},
		"round-1-is-zero": {p: chaincli.AnchorPanel{AuditMode: chaincli.AnchorAuditModePanel, Round: 1, Collecting: true}},
	} {
		p := newPanelFixture(t, "panel-off-"+name)
		p.panels.set(panel.p, panel.err)
		p.reconcile(180)
		p.deliverRound(t, testOperator("panel-x"), 2)
		p.reconcile(181)
		if p.openVer.count() != 0 || len(p.proposed()) != 0 {
			t.Fatalf("%s: OPEN_VERIFY %d, proposals %d; want none", name, p.openVer.count(), len(p.proposed()))
		}
	}
	// A chain that does not serve the query is asked once, not at every reconciliation.
	p := newPanelFixture(t, "panel-off-once")
	p.panels.set(chaincli.AnchorPanel{}, chaincli.ErrAnchorPanelUnsupported)
	for h := int64(180); h < 185; h++ {
		p.reconcile(h)
	}
	if p.panels.reads != 1 {
		t.Fatalf("an unsupported query was repeated: %d reads", p.panels.reads)
	}
}

// An ordinary (logprob) task never reads the panel state and its round 1 runs as before, with the
// panel querier present.
func TestLogprobRoundIsUntouchedByPanelSupport(t *testing.T) {
	fx := newVerifierProposalFixture(t, "panel-legacy")
	panels := &fakePanels{panel: collecting(2, 1)}
	fx.c.panels = panels
	openVerify := openVerifyCounter{link: fx.link}
	fx.setHeight(150)
	fx.chainAcceptsReceipt(t, 150)
	for _, name := range []string{"v1", "v2", "v3"} {
		fx.deliver(testOperator(name))
	}
	sent := fx.link.openVerifies()
	if openVerify.count() != 1 || sent[0].GetVerifyRound() != 1 {
		t.Fatalf("round 1 OPEN_VERIFY = %d (verify_round %d), want one for round 1", openVerify.count(), sent[0].GetVerifyRound())
	}
	got := fx.proposed()
	if len(proposalOperators(t, got)) != 3 {
		t.Fatalf("round 1 proposals = %+v, want the three hand-raises", got)
	}
	for _, hr := range got[0].VerifierHandraises {
		if hr.GetVerifyRound() != 1 {
			t.Fatalf("round 1 hand-raise proposed with verify_round %d", hr.GetVerifyRound())
		}
	}
	// A hand-raise naming a panel round is dropped by an ordinary task.
	hr := testVerifierHandraise(fx.session, fx.task, testOperator("v4"), fx.output, fx.receipt)
	hr.VerifyRound = 2
	if err := fx.c.HandleVerifierHandraise(context.Background(), testOperator("v4"), hr); err != nil {
		t.Fatal(err)
	}
	fx.fsm.onInferReceiptAccepted()
	if n := len(proposalOperators(t, fx.proposed())); n != 3 {
		t.Fatalf("a round 2 hand-raise entered a logprob task's proposals: %d", n)
	}
	if panels.reads != 0 {
		t.Fatalf("the panel state of a logprob task was read %d times", panels.reads)
	}
}
