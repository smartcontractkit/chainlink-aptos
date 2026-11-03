package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"
)

type envFlags struct {
	rpcURL        string
	deployerKey   string
	mcmsSignerKey string
	stateFile     string
	deployMaxGas  uint64
}

// state is persisted between steps.
type state struct {
	Forwarder     string `json:"forwarder,omitempty"`
	MCMS          string `json:"mcms,omitempty"`
	Adapter       string `json:"adapter,omitempty"`
	AdapterOwner  string `json:"adapter_mcms_owner,omitempty"`
	MCMSSignerKey string `json:"mcms_signer_key,omitempty"` // testnet PoC only
}

type env struct {
	ctx           context.Context
	flags         envFlags
	client        *aptos.NodeClient
	deployer      *aptos.Account
	mcmsSigner    *ecdsa.PrivateKey
	chainSelector mcmstypes.ChainSelector
	st            state
}

func newEnv(ctx context.Context, flags envFlags) (*env, error) {
	if flags.deployerKey == "" {
		return nil, errors.New("deployer key is required (--deployer-key or DEPLOYER_KEY)")
	}

	client, err := aptos.NewNodeClient(flags.rpcURL, 0)
	if err != nil {
		return nil, err
	}

	pkBytes, err := crypto.ParsePrivateKey(flags.deployerKey, crypto.PrivateKeyVariantEd25519, false)
	if err != nil {
		return nil, fmt.Errorf("parse deployer key: %w", err)
	}
	privateKey := &crypto.Ed25519PrivateKey{}
	if err := privateKey.FromBytes(pkBytes); err != nil {
		return nil, err
	}
	deployer, err := aptos.NewAccountFromSigner(privateKey)
	if err != nil {
		return nil, err
	}

	chainID, err := client.GetChainId()
	if err != nil {
		return nil, fmt.Errorf("get chain id: %w", err)
	}
	chainDetails, err := chain_selectors.GetChainDetailsByChainIDAndFamily(strconv.Itoa(int(chainID)), chain_selectors.FamilyAptos)
	if err != nil {
		return nil, fmt.Errorf("chain selector for chain id %v: %w", chainID, err)
	}

	e := &env{
		ctx:           ctx,
		flags:         flags,
		client:        client,
		deployer:      deployer,
		chainSelector: mcmstypes.ChainSelector(chainDetails.ChainSelector),
	}
	if err := e.loadState(); err != nil {
		return nil, err
	}
	if err := e.loadMCMSSigner(); err != nil {
		return nil, err
	}

	bal, err := client.AccountAPTBalance(deployer.AccountAddress())
	if err != nil {
		return nil, fmt.Errorf("get deployer balance (is %v funded?): %w", deployer.Address.StringLong(), err)
	}
	fmt.Printf("deployer %v | balance %.4f APT | chain %v (selector %v)\n",
		deployer.Address.StringLong(), float64(bal)/1e8, chainID, chainDetails.ChainSelector)
	fmt.Printf("mcms signer (EVM addr) %v\n", ethcrypto.PubkeyToAddress(e.mcmsSigner.PublicKey).Hex())

	return e, nil
}

func (e *env) loadMCMSSigner() error {
	keyHex := e.flags.mcmsSignerKey
	if keyHex == "" {
		keyHex = e.st.MCMSSignerKey
	}
	if keyHex == "" {
		key, err := ethcrypto.GenerateKey()
		if err != nil {
			return err
		}
		e.mcmsSigner = key
		e.st.MCMSSignerKey = hex.EncodeToString(ethcrypto.FromECDSA(key))
		fmt.Printf("generated new MCMS signer key, saved to %v\n", e.flags.stateFile)
		return e.saveState()
	}
	key, err := ethcrypto.HexToECDSA(strings.TrimPrefix(keyHex, "0x"))
	if err != nil {
		return fmt.Errorf("parse mcms signer key: %w", err)
	}
	e.mcmsSigner = key
	return nil
}

func (e *env) loadState() error {
	b, err := os.ReadFile(e.flags.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &e.st)
}

func (e *env) saveState() error {
	b, err := json.MarshalIndent(e.st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(e.flags.stateFile, b, 0o600)
}

func (e *env) addr(name, hexAddr string) (aptos.AccountAddress, error) {
	if hexAddr == "" {
		return aptos.AccountAddress{}, fmt.Errorf("%s address not in state file; run the step that deploys it first", name)
	}
	var a aptos.AccountAddress
	if err := a.ParseStringRelaxed(hexAddr); err != nil {
		return aptos.AccountAddress{}, fmt.Errorf("parse %s address: %w", name, err)
	}
	return a, nil
}

// wait waits for tx and returns an error including the VM status if it failed.
func (e *env) wait(err error, tx *api.PendingTransaction) (*api.UserTransaction, error) {
	if err != nil {
		return nil, err
	}
	data, err := e.client.WaitForTransaction(tx.Hash)
	if err != nil {
		return nil, fmt.Errorf("wait for tx %v: %w", tx.Hash, err)
	}
	if !data.Success {
		return data, fmt.Errorf("tx %v failed: %v", tx.Hash, data.VmStatus)
	}
	return data, nil
}
