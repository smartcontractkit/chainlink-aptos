package cre

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
)

const ed25519PublicKeyLen = 32

// resolveSigners returns the forwarder oracle keys for a DON: each node's Aptos OCR2 onchain
// signing key (ed25519, 32 bytes) for the given Aptos chain, as recorded in the job distributor.
//
// Node IDs follow the same convention as chainlink/deployment.NodeInfo: "p2p_…" peer IDs,
// "node_…" JD node IDs, otherwise CSA public keys. Every requested node must be found, enabled,
// not a bootstrap node and have exactly one Aptos OCR2 config for the chain. The keys are
// returned in ascending byte order so proposals are deterministic.
func resolveSigners(ctx context.Context, jd offchain.Client, chainSelector uint64, nodeIDs []string) ([][]byte, error) {
	if jd == nil {
		return nil, errors.New("environment has no job distributor (offchain client) to resolve DON signers")
	}
	if len(nodeIDs) == 0 {
		return nil, errors.New("no DON node IDs given")
	}
	if dup := firstDuplicate(nodeIDs); dup != "" {
		return nil, fmt.Errorf("node ID %q listed twice", dup)
	}
	chainID, err := chainselectors.GetChainIDFromSelector(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("chain ID for selector %d: %w", chainSelector, err)
	}

	filter, err := nodeFilter(nodeIDs)
	if err != nil {
		return nil, err
	}
	resp, err := jd.ListNodes(ctx, &nodev1.ListNodesRequest{Filter: filter})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	nodes := resp.GetNodes()
	if len(nodes) != len(nodeIDs) {
		return nil, fmt.Errorf("job distributor returned %d enabled nodes for %d node IDs; check that every node exists and is enabled", len(nodes), len(nodeIDs))
	}

	var errs []error
	keys := make([][]byte, 0, len(nodes))
	for _, node := range nodes {
		key, bootstrap, err := aptosSigningKey(ctx, jd, node, chainID)
		switch {
		case err != nil:
			errs = append(errs, err)
		case bootstrap:
			// Bootstrap nodes do not sign reports (same as the Stellar/EVM forwarder changesets).
		default:
			keys = append(keys, key)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	slices.SortFunc(keys, bytes.Compare)
	for i := 1; i < len(keys); i++ {
		if bytes.Equal(keys[i-1], keys[i]) {
			return nil, fmt.Errorf("two nodes share the Aptos signing key %x", keys[i])
		}
	}
	return keys, nil
}

func nodeFilter(nodeIDs []string) (*nodev1.ListNodesRequest_Filter, error) {
	hasPrefix := func(prefix string) bool { return strings.HasPrefix(nodeIDs[0], prefix) }
	for _, id := range nodeIDs[1:] {
		if strings.HasPrefix(id, "p2p_") != hasPrefix("p2p_") || strings.HasPrefix(id, "node_") != hasPrefix("node_") {
			return nil, errors.New("node IDs must all use the same form (all CSA keys, all p2p_ peer IDs or all node_ JD IDs)")
		}
	}
	switch {
	case hasPrefix("p2p_"):
		selector := strings.Join(nodeIDs, ",")
		return &nodev1.ListNodesRequest_Filter{
			Enabled: nodev1.EnableState_ENABLE_STATE_ENABLED,
			Selectors: []*ptypes.Selector{{
				Key:   "p2p_id",
				Op:    ptypes.SelectorOp_IN,
				Value: &selector,
			}},
		}, nil
	case hasPrefix("node_"):
		return &nodev1.ListNodesRequest_Filter{Enabled: nodev1.EnableState_ENABLE_STATE_ENABLED, Ids: nodeIDs}, nil
	default:
		return &nodev1.ListNodesRequest_Filter{Enabled: nodev1.EnableState_ENABLE_STATE_ENABLED, PublicKeys: nodeIDs}, nil
	}
}

// aptosSigningKey returns the node's OCR2 onchain signing key for the Aptos chain with chainID,
// or bootstrap=true for a bootstrap node (which has no signing role).
func aptosSigningKey(ctx context.Context, jd offchain.Client, node *nodev1.Node, chainID string) (key []byte, bootstrap bool, err error) {
	resp, err := jd.ListNodeChainConfigs(ctx, &nodev1.ListNodeChainConfigsRequest{
		Filter: &nodev1.ListNodeChainConfigsRequest_Filter{NodeIds: []string{node.GetId()}},
	})
	if err != nil {
		return nil, false, fmt.Errorf("list chain configs of node %s (%s): %w", node.GetName(), node.GetId(), err)
	}
	var found []*nodev1.ChainConfig
	for _, cc := range resp.GetChainConfigs() {
		if cc.GetChain().GetType() == nodev1.ChainType_CHAIN_TYPE_APTOS && cc.GetChain().GetId() == chainID {
			found = append(found, cc)
		}
	}
	switch {
	case len(found) == 0:
		return nil, false, fmt.Errorf("node %s (%s) has no Aptos chain config for chain ID %s", node.GetName(), node.GetId(), chainID)
	case len(found) > 1:
		return nil, false, fmt.Errorf("node %s (%s) has %d Aptos chain configs for chain ID %s", node.GetName(), node.GetId(), len(found), chainID)
	}
	ocr2 := found[0].GetOcr2Config()
	if ocr2.GetIsBootstrap() {
		return nil, true, nil
	}
	raw := ocr2.GetOcrKeyBundle().GetOnchainSigningAddress()
	if raw == "" {
		return nil, false, fmt.Errorf("node %s (%s) has no Aptos OCR2 onchain signing key", node.GetName(), node.GetId())
	}
	key, err = hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return nil, false, fmt.Errorf("node %s (%s): invalid Aptos onchain signing key %q: %w", node.GetName(), node.GetId(), raw, err)
	}
	if len(key) != ed25519PublicKeyLen {
		return nil, false, fmt.Errorf("node %s (%s): Aptos onchain signing key is %d bytes, want %d", node.GetName(), node.GetId(), len(key), ed25519PublicKeyLen)
	}
	return key, false, nil
}

func firstDuplicate(ids []string) string {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			return id
		}
		seen[id] = struct{}{}
	}
	return ""
}
