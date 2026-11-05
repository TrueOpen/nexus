package supportrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	testChainID     = "trueopen-fixture-1"
	testEpochLength = 40
	testEpoch       = 42
	testHeight      = 1700 // epoch 42 covers heights 1680..1719
	testSubmitter   = "trueopen1submitter"
)

// fakeChain is the chain state a test controls.
type fakeChain struct {
	mu        sync.Mutex
	height    uint64
	heightErr error
	params    chaincli.SupportParams
	paramsErr error
	nodes     map[string]chaincli.CortexNodeState
	nodeErr   error
	keys      map[string]chaincli.ServiceKeyState
	keyErr    error
	bonds     map[string]*hubv1.ServiceBondState
	bondErr   error
	rows      map[string]*hubv1.DailySupportState
	dailyErr  error
	txs       map[string]chaincli.TxResult
}

func newFakeChain() *fakeChain {
	return &fakeChain{
		height: testHeight,
		params: chaincli.SupportParams{
			EpochLengthBlocks: testEpochLength, MaxServiceMaterialExpiryBlocks: 600, MaxSupportedModelsPerOperator: 8,
			MaxConfirmationsPerBatch: 16, MaxItemsPerBatch: 64, MaxBatchBytes: 1 << 16,
		},
		nodes: map[string]chaincli.CortexNodeState{}, keys: map[string]chaincli.ServiceKeyState{},
		bonds: map[string]*hubv1.ServiceBondState{}, rows: map[string]*hubv1.DailySupportState{},
		txs: map[string]chaincli.TxResult{},
	}
}

func rowKey(operator string, epoch uint64) string { return fmt.Sprintf("%s/%d", operator, epoch) }

func (c *fakeChain) LatestHeight(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.height, c.heightErr
}

func (c *fakeChain) QuerySupportParams(context.Context) (chaincli.SupportParams, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.params, c.paramsErr
}

func (c *fakeChain) QueryCortexNode(_ context.Context, operator string) (chaincli.CortexNodeState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodeErr != nil {
		return chaincli.CortexNodeState{}, c.nodeErr
	}
	node, ok := c.nodes[operator]
	if !ok {
		return chaincli.CortexNodeState{}, chaincli.ErrNotFound
	}
	return node, nil
}

func (c *fakeChain) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keyErr != nil {
		return chaincli.ServiceKeyState{}, c.keyErr
	}
	key, ok := c.keys[operator]
	if !ok || participantType != servicekey.ParticipantCortex {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return key, nil
}

func (c *fakeChain) QueryServiceBond(_ context.Context, operator string) (*hubv1.ServiceBondState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bondErr != nil {
		return nil, c.bondErr
	}
	bond, ok := c.bonds[operator]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return bond, nil
}

func (c *fakeChain) QueryDailySupport(_ context.Context, operator string, epoch uint64) (*hubv1.DailySupportState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dailyErr != nil {
		return nil, c.dailyErr
	}
	row, ok := c.rows[rowKey(operator, epoch)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return row, nil
}

func (c *fakeChain) QueryTx(_ context.Context, txHash []byte) (chaincli.TxResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res, ok := c.txs[hex.EncodeToString(txHash)]
	if !ok {
		return chaincli.TxResult{}, chaincli.ErrNotFound
	}
	return res, nil
}

func (c *fakeChain) set(edit func(*fakeChain)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	edit(c)
}

// accept writes the DailySupport row the chain keeps for c.
func (c *fakeChain) accept(conf *hubv1.ModelSupportConfirmationV1, epoch uint64) {
	models, err := nodecontract.SupportedModelsHash(conf.GetSupportedModels())
	if err != nil {
		panic(err)
	}
	signature := sha256.Sum256(conf.GetServiceSignature())
	c.rows[rowKey(conf.GetOperatorAddress(), epoch)] = &hubv1.DailySupportState{
		Epoch: epoch, OperatorAddress: conf.GetOperatorAddress(), SupportedModelsHash: models[:], SignatureDigest: signature[:],
		AcceptedHeight: c.height + 1,
	}
}

// fakeSubmitter executes batches against a fakeChain the way the Hub does, unless told otherwise.
type fakeSubmitter struct {
	mu      sync.Mutex
	chain   *fakeChain
	batches []*hubv1.MsgBatchConfirmModelSupport
	gas     []uint64
	// poison names operators whose confirmation makes the Hub refuse the whole batch.
	poison map[string]bool
	// next, when set, is asked first: an error or a non-zero code is the answer, anything else
	// executes the batch.
	next func(msg *hubv1.MsgBatchConfirmModelSupport) (chaincli.TxResult, error)
	// pending leaves executed transactions without a block result.
	pending bool
	// noRows executes without writing DailySupport rows.
	noRows bool
}

func (s *fakeSubmitter) SubmitBatchConfirmModelSupport(_ context.Context, msg *hubv1.MsgBatchConfirmModelSupport, gas uint64) (chaincli.TxResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, proto.Clone(msg).(*hubv1.MsgBatchConfirmModelSupport))
	s.gas = append(s.gas, gas)
	if s.next != nil {
		if res, err := s.next(msg); err != nil || res.Code != 0 {
			return res, err
		}
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("tx-%d", len(s.batches))))
	result := chaincli.TxResult{TxHash: hash[:], Height: int64(testHeight + 1)}
	for _, conf := range msg.GetConfirmations() {
		if s.poison[conf.GetOperatorAddress()] {
			result.Code, result.Codespace, result.RawLog = 1148, hubCodespace, "invalid support confirmation batch"
		}
	}
	s.chain.set(func(c *fakeChain) {
		if result.Code == 0 && !s.noRows {
			for _, conf := range msg.GetConfirmations() {
				c.accept(conf, msg.GetEpochIndex())
			}
		}
		if !s.pending {
			c.txs[hex.EncodeToString(hash[:])] = result
		}
	})
	return chaincli.TxResult{TxHash: hash[:]}, nil
}

func (s *fakeSubmitter) sent() []*hubv1.MsgBatchConfirmModelSupport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*hubv1.MsgBatchConfirmModelSupport(nil), s.batches...)
}

// operator is a registered Cortex operator with its service key.
type operator struct {
	address string
	raw     []byte
	key     signer.Signer
	nonce   uint64
}

func newOperator(t *testing.T, chain *fakeChain, raw []byte, keyHex string, nonce uint64) operator {
	t.Helper()
	address, err := bech32.ConvertAndEncode("trueopen", raw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := signer.NewFromHex(keyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	op := operator{address: address, raw: raw, key: key, nonce: nonce}
	op.register(chain)
	return op
}

// register makes key the operator's current ACTIVE service key at nonce, with an ACTIVE bond.
func (op operator) register(chain *fakeChain) {
	chain.set(func(c *fakeChain) {
		c.nodes[op.address] = chaincli.CortexNodeState{
			OperatorAddress: op.address, ServiceAuthorizationNonce: op.nonce, ServiceKeyStatus: servicekey.StatusActive,
		}
		c.keys[op.address] = chaincli.ServiceKeyState{
			ParticipantType: servicekey.ParticipantCortex, OperatorAddress: op.address, ServiceAddress: op.key.Address(),
			ServicePubKey: hex.EncodeToString(op.key.PubKeyCompressed()), AuthorizationNonce: op.nonce, Status: servicekey.StatusActive,
		}
		c.bonds[op.address] = &hubv1.ServiceBondState{OperatorAddress: op.address, Status: hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_ACTIVE}
	})
}

func testModel(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// confirm signs a confirmation of op for epoch and returns its protobuf bytes.
func (op operator) confirm(t *testing.T, epoch, expiry uint64, models ...[]byte) []byte {
	t.Helper()
	if len(models) == 0 {
		models = [][]byte{testModel(1), testModel(2)}
	}
	c := Confirmation{Operator: op.address, OperatorRaw: op.raw, Models: models, Nonce: op.nonce, ExpiryHeight: expiry}
	digest, err := c.Digest(testChainID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if c.Signature, err = op.key.SignDigest(digest); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(c.Proto())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testConfig() Config {
	return Config{
		ChainID: testChainID, AddressPrefix: "trueopen", SubmitterAddress: testSubmitter,
		FlushInterval: time.Hour, FlushItems: 100, MaxQueued: 100, InclusionMarginBlocks: 3,
		GasBase: 100, GasPerConfirmation: 10, GasPerModel: 1,
		TxWait: chaincli.TxWait{Kind: "MsgBatchConfirmModelSupport", Interval: time.Millisecond, Timeout: 20 * time.Millisecond},
	}
}

func newTestRelay(t *testing.T, chain *fakeChain, sub *fakeSubmitter, store kv.Store) *Relay {
	t.Helper()
	if store == nil {
		store = kv.NewMemStore()
	}
	r, err := New(testConfig(), nil, chain, sub, store)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func wantErr(t *testing.T, name string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: err = %v, want %v", name, err, want)
	}
}
