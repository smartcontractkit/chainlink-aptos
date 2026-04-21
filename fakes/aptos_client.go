// Package fakes provides an in-process Aptos capability fake for cre-cli
// workflow simulate. FakeAptosChain satisfies aptosserver.ClientCapability
// on top of aptos-go-sdk + the local mock_forwarder bindings.
package fakes

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
)

// AptosClient embeds the full aptos.AptosRpcClient contract. It exists as a
// named interface (not a type alias) so cre-cli can type-assert client
// instances to a fakes-owned symbol, and so the generated mock_forwarder
// binding — which requires AptosRpcClient — can share the same value.
// Any future narrowing of the fake's dependency surface should happen here.
type AptosClient interface {
	aptos.AptosRpcClient
}

// NewAptosClient builds a concrete AptosClient backed by aptos-go-sdk.
// Caller supplies the fullnode REST endpoint (e.g. "https://.../v1").
func NewAptosClient(nodeURL string) (AptosClient, error) {
	cfg := aptos.NetworkConfig{NodeUrl: nodeURL}
	c, err := aptos.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("aptos.NewClient: %w", err)
	}
	return c, nil
}
