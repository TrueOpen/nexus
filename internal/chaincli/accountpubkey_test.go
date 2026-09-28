package chaincli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	authv1beta1 "cosmossdk.io/api/cosmos/auth/v1beta1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ethsecp256k1 "github.com/TrueOpen/nexus/gen/cosmosevm/crypto/v1/ethsecp256k1"
)

const testAccountAddress = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"

type fakeAuth struct {
	account *anypb.Any
	err     error
}

func (f fakeAuth) Account(context.Context, *connect.Request[authv1beta1.QueryAccountRequest]) (*connect.Response[authv1beta1.QueryAccountResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&authv1beta1.QueryAccountResponse{Account: f.account}), nil
}

func mustAny(t *testing.T, typeURL string, m proto.Message) *anypb.Any {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return &anypb.Any{TypeUrl: typeURL, Value: b}
}

func baseAccountWithKey(t *testing.T, address string, key *anypb.Any) *anypb.Any {
	return mustAny(t, baseAccountTypeURL, &authv1beta1.BaseAccount{Address: address, PubKey: key, AccountNumber: 7})
}

func TestAccountPubKey(t *testing.T) {
	key33 := append([]byte{0x02}, bytes.Repeat([]byte{0xab}, 32)...)
	ethKey := func(k []byte) *anypb.Any {
		return mustAny(t, ethSecp256k1PubKeyTypeURL, &ethsecp256k1.PubKey{Key: k})
	}
	cases := []struct {
		name     string
		auth     fakeAuth
		want     []byte
		notFound bool // otherwise, when want is nil, an error other than ErrNotFound
	}{
		{name: "stored key", auth: fakeAuth{account: baseAccountWithKey(t, testAccountAddress, ethKey(key33))}, want: key33},
		{name: "unknown account", auth: fakeAuth{err: connect.NewError(connect.CodeNotFound, errors.New("no account"))}, notFound: true},
		{name: "empty response", auth: fakeAuth{}, notFound: true},
		{name: "no key yet", auth: fakeAuth{account: baseAccountWithKey(t, testAccountAddress, nil)}, notFound: true},
		{name: "cosmos secp256k1 key", auth: fakeAuth{account: baseAccountWithKey(t, testAccountAddress,
			&anypb.Any{TypeUrl: "/cosmos.crypto.secp256k1.PubKey", Value: []byte{0x0a, 0x21}})}, notFound: true},
		{name: "key of the wrong length", auth: fakeAuth{account: baseAccountWithKey(t, testAccountAddress, ethKey(key33[:32]))}, notFound: true},
		{name: "module account", auth: fakeAuth{account: mustAny(t, "/cosmos.auth.v1beta1.ModuleAccount",
			&authv1beta1.ModuleAccount{BaseAccount: &authv1beta1.BaseAccount{Address: testAccountAddress}, Name: "fee_collector"})}, notFound: true},
		{name: "vesting account", auth: fakeAuth{account: &anypb.Any{TypeUrl: "/cosmos.vesting.v1beta1.ContinuousVestingAccount", Value: []byte{0x0a, 0x00}}}, notFound: true},
		{name: "chain unreachable", auth: fakeAuth{err: connect.NewError(connect.CodeUnavailable, errors.New("down"))}},
		{name: "answer for another address", auth: fakeAuth{account: baseAccountWithKey(t, "trueopen1other", ethKey(key33))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &client{auth: tc.auth}
			got, err := c.AccountPubKey(context.Background(), testAccountAddress)
			switch {
			case tc.want != nil:
				if err != nil || !bytes.Equal(got, tc.want) {
					t.Fatalf("got %x, %v; want %x", got, err, tc.want)
				}
			case tc.notFound:
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("err = %v, want ErrNotFound", err)
				}
			default:
				if err == nil || errors.Is(err, ErrNotFound) {
					t.Fatalf("err = %v, want a query failure", err)
				}
			}
		})
	}
}
