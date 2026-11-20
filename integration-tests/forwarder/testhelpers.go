// Package forwarder contains integration tests for governing the CRE forwarders
// (platform + platform_secondary) through MCMS via the forwarder_mcms_adapter package.
package forwarder

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmslib "github.com/smartcontractkit/mcms"
	mcmssdk "github.com/smartcontractkit/mcms/sdk"
	aptossdk "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform_secondary"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

const adapterModule = "adapter"

// deployment is everything the adapter tests act on.
type deployment struct {
	client        aptos.AptosRpcClient
	deployer      *aptos.Account
	chainSelector mcmstypes.ChainSelector

	mcmsAddress aptos.AccountAddress
	mcms        mcms.MCMS
	signerKeys  []*ecdsa.PrivateKey

	primaryAddress   aptos.AccountAddress
	primary          platform.Platform
	secondaryAddress aptos.AccountAddress
	secondary        platform_secondary.PlatformSecondary

	adapterAddress aptos.AccountAddress
	// adapterOwner is the MCMS owner account of the adapter: the address MCMS signs as when
	// calling through the adapter, and the owner of the adapter's code object.
	adapterOwner aptos.AccountAddress
}

func (d *deployment) opts() *bind.TransactOpts {
	return &bind.TransactOpts{Signer: d.deployer}
}

func (d *deployment) wait(err error, tx *api.PendingTransaction) error {
	if err != nil {
		return err
	}
	return d.waitHash(tx.Hash)
}

func (d *deployment) waitHash(hash string) error {
	data, err := d.client.WaitForTransaction(hash)
	if err != nil {
		return fmt.Errorf("wait for tx %v: %w", hash, err)
	}
	if !data.Success {
		return fmt.Errorf("tx %v failed: %v", hash, data.VmStatus)
	}
	return nil
}

func newDeployment(client aptos.AptosRpcClient, deployer *aptos.Account) (*deployment, error) {
	chainID, err := client.GetChainId()
	if err != nil {
		return nil, fmt.Errorf("get chain id: %w", err)
	}
	details, err := chain_selectors.GetChainDetailsByChainIDAndFamily(strconv.Itoa(int(chainID)), chain_selectors.FamilyAptos)
	if err != nil {
		return nil, fmt.Errorf("chain selector for chain id %v: %w", chainID, err)
	}
	return &deployment{
		client:        client,
		deployer:      deployer,
		chainSelector: mcmstypes.ChainSelector(details.ChainSelector),
	}, nil
}

// deployForwarders deploys the real platform and platform_secondary packages, owned by the
// deployer (standing in for the native multisig that owns them in production).
func (d *deployment) deployForwarders() error {
	addr, tx, p, err := platform.DeployToObject(d.deployer, d.client, d.deployer.AccountAddress())
	if err := d.wait(err, tx); err != nil {
		return fmt.Errorf("deploy platform: %w", err)
	}
	d.primaryAddress, d.primary = addr, p

	addr, tx, s, err := platform_secondary.DeployToObject(d.deployer, d.client, d.deployer.AccountAddress())
	if err := d.wait(err, tx); err != nil {
		return fmt.Errorf("deploy platform_secondary: %w", err)
	}
	d.secondaryAddress, d.secondary = addr, s
	return nil
}

// deployMCMS deploys MCMS, configures the bypasser role as 2-of-2 with fresh signer keys, and
// makes MCMS own itself (required before MCMS can publish code via mcms_deployer).
func (d *deployment) deployMCMS(ctx context.Context) error {
	seed := mcms.DefaultSeed + time.Now().String()
	addr, tx, contract, err := mcms.DeployToResourceAccount(d.deployer, d.client, seed)
	if err := d.wait(err, tx); err != nil {
		return fmt.Errorf("deploy mcms: %w", err)
	}
	d.mcmsAddress, d.mcms = addr, contract

	signers := make([]common.Address, 2)
	d.signerKeys = make([]*ecdsa.PrivateKey, 2)
	for i := range signers {
		key, err := ethcrypto.GenerateKey()
		if err != nil {
			return err
		}
		d.signerKeys[i] = key
		signers[i] = ethcrypto.PubkeyToAddress(key.PublicKey)
	}
	slices.SortFunc(signers, func(a, b common.Address) int { return a.Cmp(b) })

	configurer := aptossdk.NewConfigurer(d.client, d.deployer, aptossdk.TimelockRoleBypasser)
	res, err := configurer.SetConfig(ctx, d.mcmsAddress.StringLong(), &mcmstypes.Config{Quorum: 2, Signers: signers}, false)
	if err != nil {
		return fmt.Errorf("set bypasser config: %w", err)
	}
	if err := d.waitHash(res.Hash); err != nil {
		return fmt.Errorf("set bypasser config: %w", err)
	}

	tx, err = d.mcms.MCMSAccount().TransferOwnershipToSelf(d.opts())
	if err := d.wait(err, tx); err != nil {
		return fmt.Errorf("transfer mcms ownership to self: %w", err)
	}
	op, err := d.mcmsOp(d.mcms.MCMSAccount().Encoder().AcceptOwnership())
	if err != nil {
		return err
	}
	if err := d.executeProposal(ctx, "MCMS accepts ownership of itself", op); err != nil {
		return fmt.Errorf("accept mcms self-ownership: %w", err)
	}
	return nil
}

// adapterNamedAddresses returns the named addresses to compile the adapter against the deployed
// forwarders and MCMS, at the given adapter address.
func (d *deployment) adapterNamedAddresses(adapterAddress aptos.AccountAddress) map[string]aptos.AccountAddress {
	return map[string]aptos.AccountAddress{
		"forwarder_mcms_adapter": adapterAddress,
		"mcms":                   d.mcmsAddress,
		"platform":               d.primaryAddress,
		"platform_secondary":     d.secondaryAddress,
		// only needed to compile the forwarder dependencies
		"owner":           d.deployer.AccountAddress(),
		"owner_secondary": d.deployer.AccountAddress(),
	}
}

// publishAdapter publishes the adapter through MCMS (mcms_deployer), so its code object is owned
// by MCMS from the start.
func (d *deployment) publishAdapter(ctx context.Context) error {
	registry := d.mcms.MCMSRegistry()
	seed := fmt.Sprintf("forwarder_mcms_adapter_%d", time.Now().UnixNano())

	adapterAddress, err := registry.GetNewCodeObjectAddress(nil, []byte(seed))
	if err != nil {
		return fmt.Errorf("get new code object address: %w", err)
	}
	adapterOwner, err := registry.GetNewCodeObjectOwnerAddress(nil, []byte(seed))
	if err != nil {
		return fmt.Errorf("get new code object owner address: %w", err)
	}

	payload, err := compile.CompilePackage(contracts.ForwarderMcmsAdapter, d.adapterNamedAddresses(adapterAddress))
	if err != nil {
		return fmt.Errorf("compile adapter: %w", err)
	}
	ops, err := utils.CreateChunksAndStage(payload, d.mcms, uint64(d.chainSelector), seed, nil)
	if err != nil {
		return fmt.Errorf("create publish ops: %w", err)
	}
	if err := d.executeProposal(ctx, "Publish forwarder_mcms_adapter", ops...); err != nil {
		return fmt.Errorf("publish adapter: %w", err)
	}
	d.adapterAddress, d.adapterOwner = adapterAddress, adapterOwner
	return nil
}

// adapterCall builds an MCMS op calling adapter::<function> with the given BCS-encoded args.
func (d *deployment) adapterCall(function string, types []string, values []any) (mcmstypes.Operation, error) {
	data, err := bcsArgs(types, values)
	if err != nil {
		return mcmstypes.Operation{}, err
	}
	tx, err := aptossdk.NewTransaction(
		string(contracts.ForwarderMcmsAdapter),
		adapterModule,
		function,
		d.adapterAddress,
		data,
		"ForwarderMcmsAdapter",
		nil,
	)
	if err != nil {
		return mcmstypes.Operation{}, err
	}
	return mcmstypes.Operation{ChainSelector: d.chainSelector, Transaction: tx}, nil
}

// mcmsOp builds an MCMS op from a binding encoder result targeting an MCMS module.
func (d *deployment) mcmsOp(module bind.ModuleInformation, function string, _ []aptos.TypeTag, args [][]byte, err error) (mcmstypes.Operation, error) {
	if err != nil {
		return mcmstypes.Operation{}, err
	}
	tx, err := utils.GenerateMCMSTx(d.mcmsAddress, module, function, args)
	if err != nil {
		return mcmstypes.Operation{}, err
	}
	return mcmstypes.Operation{ChainSelector: d.chainSelector, Transaction: tx}, nil
}

// executeProposal builds a bypasser proposal with one batch per op, signs it with every MCMS
// signer (2-of-2), sets the root and executes all ops in order.
func (d *deployment) executeProposal(ctx context.Context, description string, ops ...mcmstypes.Operation) error {
	inspector := aptossdk.NewInspector(d.client, aptossdk.TimelockRoleBypasser)
	opCount, err := inspector.GetOpCount(ctx, d.mcmsAddress.StringLong())
	if err != nil {
		return fmt.Errorf("get op count: %w", err)
	}
	metadata, err := json.Marshal(aptossdk.AdditionalFieldsMetadata{Role: aptossdk.TimelockRoleBypasser})
	if err != nil {
		return err
	}

	builder := mcmslib.NewTimelockProposalBuilder().
		SetVersion("v1").
		SetValidUntil(uint32(time.Now().Add(time.Hour).Unix())).
		SetDescription(description).
		// Some tests intentionally fail an op, which leaves the previous root with pending ops;
		// overriding lets the next proposal proceed.
		SetOverridePreviousRoot(true).
		AddTimelockAddress(d.chainSelector, d.mcmsAddress.StringLong()).
		AddChainMetadata(d.chainSelector, mcmstypes.ChainMetadata{
			StartingOpCount:  opCount,
			MCMAddress:       d.mcmsAddress.StringLong(),
			AdditionalFields: metadata,
		}).
		SetAction(mcmstypes.TimelockActionBypass)
	for _, op := range ops {
		if op.Transaction.Data == nil {
			// the proposal validator rejects nil data; no-arg calls need an empty slice
			op.Transaction.Data = []byte{}
		}
		builder.AddOperation(mcmstypes.BatchOperation{
			ChainSelector: d.chainSelector,
			Transactions:  []mcmstypes.Transaction{op.Transaction},
		})
	}
	timelockProposal, err := builder.Build()
	if err != nil {
		return fmt.Errorf("build proposal: %w", err)
	}

	proposal, _, err := timelockProposal.Convert(ctx, map[mcmstypes.ChainSelector]mcmssdk.TimelockConverter{
		d.chainSelector: aptossdk.NewTimelockConverter(),
	})
	if err != nil {
		return fmt.Errorf("convert proposal: %w", err)
	}
	signable, err := mcmslib.NewSignable(&proposal, map[mcmstypes.ChainSelector]mcmssdk.Inspector{
		d.chainSelector: inspector,
	})
	if err != nil {
		return fmt.Errorf("create signable: %w", err)
	}
	for _, key := range d.signerKeys {
		if _, err := signable.SignAndAppend(mcmslib.NewPrivateKeySigner(key)); err != nil {
			return fmt.Errorf("sign proposal: %w", err)
		}
	}
	if quorum, err := signable.ValidateSignatures(ctx); err != nil || !quorum {
		return fmt.Errorf("quorum not met (err: %w)", err)
	}

	encoders, err := proposal.GetEncoders()
	if err != nil {
		return fmt.Errorf("get encoders: %w", err)
	}
	executable, err := mcmslib.NewExecutable(&proposal, map[mcmstypes.ChainSelector]mcmssdk.Executor{
		d.chainSelector: aptossdk.NewExecutor(d.client, d.deployer, encoders[d.chainSelector].(*aptossdk.Encoder), aptossdk.TimelockRoleBypasser),
	})
	if err != nil {
		return fmt.Errorf("create executable: %w", err)
	}
	res, err := executable.SetRoot(ctx, d.chainSelector)
	if err != nil {
		return fmt.Errorf("set root: %w", err)
	}
	if err := d.waitHash(res.Hash); err != nil {
		return fmt.Errorf("set root: %w", err)
	}
	for i := range proposal.Operations {
		res, err := executable.Execute(ctx, i)
		if err != nil {
			return fmt.Errorf("execute op %d: %w", i, err)
		}
		if err := d.waitHash(res.Hash); err != nil {
			return fmt.Errorf("execute op %d: %w", i, err)
		}
	}
	return nil
}

// view calls a no-arg view function on the adapter.
func (d *deployment) adapterView(function string, out any) error {
	c := bind.NewBoundContract(d.adapterAddress, string(contracts.ForwarderMcmsAdapter), adapterModule, d.client)
	module, fn, typeTags, args, err := c.Encode(function, nil, nil, nil)
	if err != nil {
		return err
	}
	res, err := c.Call(nil, module, fn, typeTags, args)
	if err != nil {
		return fmt.Errorf("view %s: %w", function, err)
	}
	return codec.DecodeAptosJsonArray(res, out)
}

// codeObjectOwner reads 0x1::object::ObjectCore.owner, i.e. who can upgrade a code object.
func (d *deployment) codeObjectOwner(obj aptos.AccountAddress) (aptos.AccountAddress, error) {
	var owner aptos.AccountAddress
	nodeClient, ok := d.client.(*aptos.NodeClient)
	if !ok {
		return owner, fmt.Errorf("client is %T, need *aptos.NodeClient", d.client)
	}
	res, err := nodeClient.AccountResource(obj, "0x1::object::ObjectCore")
	if err != nil {
		return owner, err
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return owner, fmt.Errorf("unexpected ObjectCore resource: %v", res)
	}
	s, ok := data["owner"].(string)
	if !ok {
		return owner, fmt.Errorf("unexpected ObjectCore owner: %v", data["owner"])
	}
	return owner, owner.ParseStringRelaxed(s)
}

// requireAbort asserts err is a Move abort with the given error name or hex code.
func requireAbort(t *testing.T, err error, name, code string) {
	t.Helper()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), name) || strings.Contains(err.Error(), code),
		"expected abort %s (%s), got: %v", name, code, err)
}

// bcsArgs BCS-encodes and concatenates args: the `data` format mcms_entrypoint decodes.
func bcsArgs(types []string, values []any) ([]byte, error) {
	c := bind.NewBoundContract(aptos.AccountAddress{}, "", "", nil)
	_, _, _, args, err := c.Encode("", nil, types, values)
	if err != nil {
		return nil, err
	}
	return aptossdk.ArgsToData(args), nil
}

// oracleKeys returns n distinct 32-byte ed25519 public keys.
func oracleKeys(n int) ([][]byte, error) {
	keys := make([][]byte, n)
	for i := range keys {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		keys[i] = pub
	}
	return keys, nil
}
