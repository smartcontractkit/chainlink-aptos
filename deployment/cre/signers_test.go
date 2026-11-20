package cre

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
)

// fakeJD implements the two node-service calls resolveSigners uses.
type fakeJD struct {
	offchain.Client
	nodes   []*nodev1.Node
	configs map[string][]*nodev1.ChainConfig // by node ID
}

func (f *fakeJD) ListNodes(_ context.Context, in *nodev1.ListNodesRequest, _ ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	filter := in.GetFilter()
	var p2pIDs []string
	for _, s := range filter.GetSelectors() {
		if s.GetKey() == "p2p_id" && s.GetOp() == ptypes.SelectorOp_IN {
			p2pIDs = strings.Split(s.GetValue(), ",")
		}
	}
	var out []*nodev1.Node
	for _, n := range f.nodes {
		if !n.GetIsEnabled() {
			continue
		}
		switch {
		case len(filter.GetIds()) > 0 && !slices.Contains(filter.GetIds(), n.GetId()):
			continue
		case len(filter.GetPublicKeys()) > 0 && !slices.Contains(filter.GetPublicKeys(), n.GetPublicKey()):
			continue
		case len(p2pIDs) > 0 && !slices.ContainsFunc(n.GetLabels(), func(l *ptypes.Label) bool {
			return l.GetKey() == "p2p_id" && slices.Contains(p2pIDs, l.GetValue())
		}):
			continue
		}
		out = append(out, n)
	}
	return &nodev1.ListNodesResponse{Nodes: out}, nil
}

func (f *fakeJD) ListNodeChainConfigs(_ context.Context, in *nodev1.ListNodeChainConfigsRequest, _ ...grpc.CallOption) (*nodev1.ListNodeChainConfigsResponse, error) {
	var out []*nodev1.ChainConfig
	for _, id := range in.GetFilter().GetNodeIds() {
		out = append(out, f.configs[id]...)
	}
	return &nodev1.ListNodeChainConfigsResponse{ChainConfigs: out}, nil
}

func aptosConfig(chainID, signingKey string, bootstrap bool) *nodev1.ChainConfig {
	return &nodev1.ChainConfig{
		Chain: &nodev1.Chain{Id: chainID, Type: nodev1.ChainType_CHAIN_TYPE_APTOS},
		Ocr2Config: &nodev1.OCR2Config{
			IsBootstrap:  bootstrap,
			OcrKeyBundle: &nodev1.OCR2Config_OCRKeyBundle{OnchainSigningAddress: signingKey},
		},
	}
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// newFakeJD returns n enabled nodes, node_i with CSA key csa_i and peer p2p_i, each with an Aptos
// testnet config whose signing key is 32 bytes of (n - i), so ID order and key order differ.
func newFakeJD(n int) (*fakeJD, []string) {
	f := &fakeJD{configs: map[string][]*nodev1.ChainConfig{}}
	var csaKeys []string
	for i := range n {
		id := "node_" + string(rune('a'+i))
		csa := "csa" + string(rune('a'+i))
		f.nodes = append(f.nodes, &nodev1.Node{
			Id: id, Name: "n" + id, PublicKey: csa, IsEnabled: true,
			Labels: []*ptypes.Label{{Key: "p2p_id", Value: ptr("p2p_" + string(rune('a'+i)))}},
		})
		f.configs[id] = []*nodev1.ChainConfig{
			{Chain: &nodev1.Chain{Id: "11155111", Type: nodev1.ChainType_CHAIN_TYPE_EVM}},
			aptosConfig("2", hex.EncodeToString(key(byte(n-i))), false),
		}
		csaKeys = append(csaKeys, csa)
	}
	return f, csaKeys
}

func ptr[T any](v T) *T { return &v }

func TestResolveSigners(t *testing.T) {
	ctx := t.Context()
	sel := chainselectors.APTOS_TESTNET.Selector

	t.Run("by CSA key, sorted by key bytes", func(t *testing.T) {
		jd, csa := newFakeJD(4)
		keys, err := resolveSigners(ctx, jd, sel, csa)
		require.NoError(t, err)
		require.Equal(t, [][]byte{key(1), key(2), key(3), key(4)}, keys)
	})

	t.Run("by p2p and node IDs", func(t *testing.T) {
		jd, _ := newFakeJD(4)
		keys, err := resolveSigners(ctx, jd, sel, []string{"p2p_a", "p2p_b", "p2p_c", "p2p_d"})
		require.NoError(t, err)
		require.Len(t, keys, 4)
		keys, err = resolveSigners(ctx, jd, sel, []string{"node_a", "node_b"})
		require.NoError(t, err)
		require.Equal(t, [][]byte{key(3), key(4)}, keys)
	})

	t.Run("0x-prefixed key", func(t *testing.T) {
		jd, csa := newFakeJD(1)
		jd.configs["node_a"] = []*nodev1.ChainConfig{aptosConfig("2", "0x"+hex.EncodeToString(key(9)), false)}
		keys, err := resolveSigners(ctx, jd, sel, csa)
		require.NoError(t, err)
		require.Equal(t, [][]byte{key(9)}, keys)
	})

	t.Run("bootstrap nodes are skipped", func(t *testing.T) {
		jd, csa := newFakeJD(3)
		jd.configs["node_b"] = []*nodev1.ChainConfig{aptosConfig("2", "", true)}
		keys, err := resolveSigners(ctx, jd, sel, csa)
		require.NoError(t, err)
		require.Equal(t, [][]byte{key(1), key(3)}, keys)
	})

	for name, tc := range map[string]struct {
		mutate  func(*fakeJD)
		ids     []string
		wantErr string
	}{
		"unknown node": {
			ids: []string{"csaa", "nope"}, wantErr: "returned 1 enabled nodes for 2 node IDs",
		},
		"disabled node": {
			mutate: func(f *fakeJD) { f.nodes[1].IsEnabled = false },
			ids:    []string{"csaa", "csab"}, wantErr: "returned 1 enabled nodes",
		},
		"duplicate ID": {
			ids: []string{"csaa", "csaa"}, wantErr: "listed twice",
		},
		"mixed ID forms": {
			ids: []string{"csaa", "p2p_b"}, wantErr: "same form",
		},
		"no aptos config for this chain": {
			mutate: func(f *fakeJD) {
				f.configs["node_a"] = []*nodev1.ChainConfig{aptosConfig("1", hex.EncodeToString(key(1)), false)}
			},
			ids: []string{"csaa"}, wantErr: "no Aptos chain config for chain ID 2",
		},
		"wrong key length": {
			mutate: func(f *fakeJD) { f.configs["node_a"] = []*nodev1.ChainConfig{aptosConfig("2", "abcd", false)} },
			ids:    []string{"csaa"}, wantErr: "is 2 bytes, want 32",
		},
		"missing key": {
			mutate: func(f *fakeJD) { f.configs["node_a"] = []*nodev1.ChainConfig{aptosConfig("2", "", false)} },
			ids:    []string{"csaa"}, wantErr: "no Aptos OCR2 onchain signing key",
		},
		"shared key": {
			mutate: func(f *fakeJD) {
				f.configs["node_b"] = []*nodev1.ChainConfig{aptosConfig("2", hex.EncodeToString(key(2)), false)}
				f.configs["node_a"] = []*nodev1.ChainConfig{aptosConfig("2", hex.EncodeToString(key(2)), false)}
			},
			ids: []string{"csaa", "csab"}, wantErr: "share the Aptos signing key",
		},
	} {
		t.Run(name, func(t *testing.T) {
			jd, _ := newFakeJD(2)
			if tc.mutate != nil {
				tc.mutate(jd)
			}
			_, err := resolveSigners(ctx, jd, sel, tc.ids)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}

	t.Run("no job distributor", func(t *testing.T) {
		_, err := resolveSigners(ctx, nil, sel, []string{"csaa"})
		require.ErrorContains(t, err, "no job distributor")
	})
}
