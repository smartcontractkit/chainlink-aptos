package forwarder

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

// Test_ForwarderMcmsAdapter deploys the real platform + platform_secondary forwarders, MCMS and
// the forwarder_mcms_adapter (published by MCMS) on an Aptos localnet, hands both forwarders to
// MCMS, and drives set_config / clear_config / transfer_ownership through MCMS proposals.
func Test_ForwarderMcmsAdapter(t *testing.T) {
	lggr := logger.Test(t)
	ctx := t.Context()

	b, err := blockchain.NewBlockchainNetwork(&blockchain.Input{Type: blockchain.TypeAptos})
	require.NoError(t, err)
	rpcURL := b.Nodes[0].ExternalHTTPUrl + "/v1"
	lggr.Infof("Started Aptos localnet at %s", rpcURL)

	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)
	pkBytes, err := crypto.ParsePrivateKey(blockchain.DefaultAptosPrivateKey, crypto.PrivateKeyVariantEd25519, false)
	require.NoError(t, err)
	privateKey := &crypto.Ed25519PrivateKey{}
	require.NoError(t, privateKey.FromBytes(pkBytes))
	deployer, err := aptos.NewAccountFromSigner(privateKey)
	require.NoError(t, err)

	d, err := newDeployment(client, deployer)
	require.NoError(t, err)

	// ===== Deploy =====
	require.NoError(t, d.deployForwarders())
	lggr.Infof("platform at %s, platform_secondary at %s", d.primaryAddress.StringLong(), d.secondaryAddress.StringLong())

	require.NoError(t, d.deployMCMS(ctx))
	mcmsOwner, err := d.mcms.MCMSAccount().Owner(nil)
	require.NoError(t, err)
	require.Equal(t, d.mcmsAddress, mcmsOwner, "MCMS must own itself")
	lggr.Infof("MCMS at %s (self-owned, 2-of-2 bypasser)", d.mcmsAddress.StringLong())

	require.NoError(t, d.publishAdapter(ctx))
	lggr.Infof("adapter published by MCMS at %s, MCMS owner account %s", d.adapterAddress.StringLong(), d.adapterOwner.StringLong())

	t.Run("adapter code is owned by MCMS", func(t *testing.T) {
		var registered aptos.AccountAddress
		require.NoError(t, d.adapterView("mcms_owner_address", &registered))
		require.Equal(t, d.adapterOwner, registered)

		codeOwner, err := d.codeObjectOwner(d.adapterAddress)
		require.NoError(t, err)
		require.Equal(t, d.adapterOwner, codeOwner, "only MCMS may upgrade the adapter")

		owned, err := d.mcms.MCMSRegistry().IsOwnedCodeObject(nil, d.adapterAddress)
		require.NoError(t, err)
		require.True(t, owned)
	})

	t.Run("adapter cannot be published outside MCMS", func(t *testing.T) {
		// An EOA-published copy would leave upgrade authority with the EOA; init_module refuses.
		addr, tx, err := bind.DeployPackageToObject(d.deployer, d.client, contracts.ForwarderMcmsAdapter,
			d.adapterNamedAddresses(aptos.AccountAddress{}), // overwritten with the object address
		)
		err = d.wait(err, tx)
		require.Error(t, err, "EOA publish of the adapter at %s must fail", addr.StringLong())
		// The EOA's code object exists but is not registered with MCMS, so
		// mcms_registry::is_owned_code_object aborts inside init_module.
		requireAbort(t, err, "E_ADDRESS_NOT_REGISTERED", "0x1000a")
	})

	// ===== Hand both forwarders to MCMS =====
	require.True(t, t.Run("hand both forwarders to MCMS", func(t *testing.T) {
		// Current owner (native multisig in production) proposes the adapter's MCMS owner ...
		tx, err := d.primary.Forwarder().TransferOwnership(d.opts(), d.adapterOwner)
		require.NoError(t, d.wait(err, tx))
		tx, err = d.secondary.Forwarder().TransferOwnership(d.opts(), d.adapterOwner)
		require.NoError(t, d.wait(err, tx))

		// ... and ONE MCMS proposal accepts both through the adapter.
		acceptPrimary, err := d.adapterCall("accept_ownership", []string{"address"}, []any{d.primaryAddress})
		require.NoError(t, err)
		acceptSecondary, err := d.adapterCall("accept_ownership", []string{"address"}, []any{d.secondaryAddress})
		require.NoError(t, err)
		require.NoError(t, d.executeProposal(ctx, "Accept forwarder ownership", acceptPrimary, acceptSecondary))

		owner, err := d.primary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, d.adapterOwner, owner)
		owner, err = d.secondary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, d.adapterOwner, owner)
	}))

	// ===== set_config / clear_config via MCMS =====
	oraclesPrimary, err := oracleKeys(4) // f = 1 needs 3f+1 = 4
	require.NoError(t, err)
	oraclesSecondary, err := oracleKeys(7) // f = 2 needs 7
	require.NoError(t, err)

	t.Run("set_config on both forwarders in one proposal", func(t *testing.T) {
		setPrimary, err := d.adapterCall("set_config",
			[]string{"address", "u32", "u32", "u8", "vector<vector<u8>>"},
			[]any{d.primaryAddress, uint32(1), uint32(1), uint8(1), oraclesPrimary})
		require.NoError(t, err)
		setSecondary, err := d.adapterCall("set_config",
			[]string{"address", "u32", "u32", "u8", "vector<vector<u8>>"},
			[]any{d.secondaryAddress, uint32(2), uint32(3), uint8(2), oraclesSecondary})
		require.NoError(t, err)
		require.NoError(t, d.executeProposal(ctx, "Set forwarder configs", setPrimary, setSecondary))

		f, oracles, err := d.getConfig(d.primaryAddress, contracts.Platform, 1, 1)
		require.NoError(t, err)
		require.Equal(t, uint8(1), f)
		require.Equal(t, hexKeys(oraclesPrimary), oracles)

		f, oracles, err = d.getConfig(d.secondaryAddress, contracts.PlatformSecondary, 2, 3)
		require.NoError(t, err)
		require.Equal(t, uint8(2), f)
		require.Equal(t, hexKeys(oraclesSecondary), oracles)

		// Each call only touched its own forwarder.
		_, _, err = d.getConfig(d.secondaryAddress, contracts.PlatformSecondary, 1, 1)
		require.Error(t, err)
		_, _, err = d.getConfig(d.primaryAddress, contracts.Platform, 2, 3)
		require.Error(t, err)
	})

	t.Run("previous owner can no longer set config", func(t *testing.T) {
		tx, err := d.primary.Forwarder().SetConfig(d.opts(), 9, 9, 1, oraclesPrimary)
		requireAbort(t, d.wait(err, tx), "E_NOT_OWNER", "0x50007")
		tx, err = d.secondary.Forwarder().SetConfig(d.opts(), 9, 9, 1, oraclesPrimary)
		requireAbort(t, d.wait(err, tx), "E_NOT_OWNER", "0x50007")
	})

	t.Run("clear_config", func(t *testing.T) {
		clearOp, err := d.adapterCall("clear_config", []string{"address", "u32", "u32"}, []any{d.primaryAddress, uint32(1), uint32(1)})
		require.NoError(t, err)
		require.NoError(t, d.executeProposal(ctx, "Clear primary config", clearOp))

		_, _, err = d.getConfig(d.primaryAddress, contracts.Platform, 1, 1)
		require.Error(t, err, "primary config (1,1) must be gone")
		_, _, err = d.getConfig(d.secondaryAddress, contracts.PlatformSecondary, 2, 3)
		require.NoError(t, err, "secondary config must be untouched")
	})

	t.Run("unknown forwarder is rejected", func(t *testing.T) {
		bogus := d.deployer.AccountAddress()
		op, err := d.adapterCall("clear_config", []string{"address", "u32", "u32"}, []any{bogus, uint32(2), uint32(3)})
		require.NoError(t, err)
		err = d.executeProposal(ctx, "Clear config on unknown forwarder", op)
		requireAbort(t, err, "E_UNKNOWN_FORWARDER", "0x10002")
	})

	t.Run("MCMS can hand ownership back out", func(t *testing.T) {
		// A failed op leaves the previous root with a pending op; this proposal replaces it.
		op, err := d.adapterCall("transfer_ownership", []string{"address", "address"}, []any{d.secondaryAddress, d.deployer.AccountAddress()})
		require.NoError(t, err)
		require.NoError(t, d.executeProposal(ctx, "Hand secondary back", op))

		tx, err := d.secondary.Forwarder().AcceptOwnership(d.opts())
		require.NoError(t, d.wait(err, tx))

		owner, err := d.secondary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, d.deployer.AccountAddress(), owner)
		owner, err = d.primary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, d.adapterOwner, owner, "primary stays with MCMS")
	})
}

// getConfig reads forwarder::get_config(don_id, config_version) and returns f and the oracle keys
// as 0x-hex. The generated binding's Config omits the oracles, so this decodes the raw view.
func (d *deployment) getConfig(fwd aptos.AccountAddress, pkg contracts.Package, donID, version uint32) (uint8, []string, error) {
	c := bind.NewBoundContract(fwd, string(pkg), "forwarder", d.client)
	module, fn, typeTags, args, err := c.Encode("get_config", nil, []string{"u32", "u32"}, []any{donID, version})
	if err != nil {
		return 0, nil, err
	}
	res, err := c.Call(nil, module, fn, typeTags, args)
	if err != nil {
		return 0, nil, err
	}
	if len(res) != 1 {
		return 0, nil, fmt.Errorf("unexpected get_config result: %v", res)
	}
	cfg, ok := res[0].(map[string]any)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected get_config result: %v", res[0])
	}
	var f uint8
	switch v := cfg["f"].(type) {
	case float64:
		f = uint8(v)
	case string:
		_, err := fmt.Sscan(v, &f)
		if err != nil {
			return 0, nil, err
		}
	default:
		return 0, nil, fmt.Errorf("unexpected f: %v", cfg["f"])
	}
	rawOracles, ok := cfg["oracles"].([]any)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected oracles: %v", cfg["oracles"])
	}
	oracles := make([]string, len(rawOracles))
	for i, o := range rawOracles {
		m, ok := o.(map[string]any)
		if !ok {
			return 0, nil, fmt.Errorf("unexpected oracle: %v", o)
		}
		oracles[i], _ = m["bytes"].(string)
	}
	return f, oracles, nil
}

func hexKeys(keys [][]byte) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = "0x" + hex.EncodeToString(k)
	}
	return out
}
