package ccip

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	aptoscrypto "github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	cciprouter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router"
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-integrations/evm/utils"
)

func TestDeployCCIP(t *testing.T) {
	var pk aptoscrypto.Ed25519PrivateKey
	pk.FromHex(os.Getenv("PRIVATE_KEY"))
	account, _ := aptos.NewAccountFromSigner(&pk)
	testnetClient, _ := aptos.NewNodeClient("https://api.testnet.aptoslabs.com/v1", 0)

	acc, err := testnetClient.Account(account.Address)
	require.NoError(t, err)
	acc.SequenceNumber()

	mcmsAddress, mcmsPendingTx, _, err := mcms.DeployToResourceAccount(account, testnetClient, time.Now().String())
	require.NoError(t, err)
	data, err := testnetClient.WaitForTransaction(mcmsPendingTx.TxnHash())
	require.NoError(t, err)
	require.True(t, data.Success, "transaction failed", data.VmStatus)
	fmt.Println("Deployed MCMS to address: ", mcmsAddress.StringLong())

	address, tx, ccip, err := DeployToObject(account, testnetClient, mcmsAddress, false)
	require.NoError(t, err)
	data, err = testnetClient.WaitForTransaction(tx.TxnHash())
	require.NoError(t, err)
	require.True(t, data.Success, "transaction failed", data.VmStatus)

	fmt.Println("Deployed CCIP to address:", address.StringLong())
	fmt.Println("Transaction hash:", tx.TxnHash())

	tx, ccipRouter, err := cciprouter.DeployToExistingObject(account, testnetClient, address, address, mcmsAddress)
	require.NoError(t, err)
	data, err = testnetClient.WaitForTransaction(tx.TxnHash())
	require.NoError(t, err)
	require.True(t, data.Success, "transaction failed", data.VmStatus)
	_ = ccipRouter

	opts := &bind.TransactOpts{Signer: account}
	token := aptos.AccountAddress{}
	token.ParseStringRelaxed("0xa")
	evmFamilySelector, _ := hex.DecodeString("2812d52c")

	{
		fmt.Println("RMNRemote.Initialize")
		tx, err = ccip.RMNRemote.Initialize(opts, 743186221051783445)
		assert.NoError(t, err)
		data, err = testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	// {
	// 	fmt.Println("ReceiverRegistry.Initialize")
	// 	tx, err = ccip.ReceiverRegistry.Initialize(opts)
	// 	assert.NoError(t, err)
	// 	data, err = testnetClient.WaitForTransaction(tx.Hash)
	// 	assert.NoError(t, err)
	// 	assert.True(t, data.Success, "transaction failed", data.VmStatus)
	// }
	{
		fmt.Println("Onramp.Initialize")
		tx, err = ccip.Onramp.Initialize(opts, 743186221051783445, account.AccountAddress(), []uint64{16015286601757825753}, []bool{true}, []bool{false})
		assert.NoError(t, err)
		data, err = testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	{
		fmt.Println("Offramp.Initialize")
		tx, err = ccip.Offramp.Initialize(opts, 743186221051783445, 30, []uint64{16015286601757825753}, []bool{true}, []bool{true}, [][]byte{[]byte("0x1234567890")})
		assert.NoError(t, err)
		data, err = testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	{
		fmt.Println("FeeQuoter.Initialize")
		tx, err = ccip.FeeQuoter.Initialize(opts, 1000, token, 12400, []aptos.AccountAddress{token})
		assert.NoError(t, err)
		data, err = testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	// {
	// 	fmt.Println("TokenAdminRegistry.Initialize")
	// 	tx, err = ccip.TokenAdminRegistry.Initialize(opts)
	// 	assert.NoError(t, err)
	// 	data, err = testnetClient.WaitForTransaction(tx.Hash)
	// 	assert.NoError(t, err)
	// 	assert.True(t, data.Success, "transaction failed", data.VmStatus)
	// }
	{
		fmt.Println("FeeQuoter.ApplyFeeTokenUpdates")
		tx, err := ccip.FeeQuoter.ApplyFeeTokenUpdates(opts, nil, []aptos.AccountAddress{token})
		assert.NoError(t, err)
		data, err := testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	{
		fmt.Println("FeeQuoter.ApplyTokenTransferFeeConfigUpdates")
		tx, err := ccip.FeeQuoter.ApplyTokenTransferFeeConfigUpdates(opts, 16015286601757825753, []aptos.AccountAddress{token}, []uint32{1}, []uint32{10000}, []uint16{0}, []uint32{1000}, []uint32{1000}, []bool{true}, nil)
		assert.NoError(t, err)
		data, err := testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	{
		fmt.Println("FeeQuoter.ApplyDestChainConfigUpdates")
		tx, err := ccip.FeeQuoter.ApplyDestChainConfigUpdates(opts,
			16015286601757825753,
			true,
			1,
			10000,
			7000000,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			evmFamilySelector,
			false,
			0,
			0,
			1000000,
			0,
			10000000,
			0,
		)
		assert.NoError(t, err)
		data, err := testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	{
		fmt.Println("FeeQuoter.UpdatePrices")
		tx, err := ccip.FeeQuoter.UpdatePrices(opts, []aptos.AccountAddress{token}, []*big.Int{big.NewInt(1000)}, []uint64{16015286601757825753}, []*big.Int{big.NewInt(0)})
		assert.NoError(t, err)
		data, err := testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
	{
		fmt.Println("FeeQuoter.ApplyPremiumMultiplierWeiPerEthUpdates")
		tx, err := ccip.FeeQuoter.ApplyPremiumMultiplierWeiPerEthUpdates(opts, []aptos.AccountAddress{token}, []uint64{1})
		assert.NoError(t, err)
		data, err := testnetClient.WaitForTransaction(tx.Hash)
		assert.NoError(t, err)
		assert.True(t, data.Success, "transaction failed", data.VmStatus)
	}
}

func TestSend(t *testing.T) {
	var pk aptoscrypto.Ed25519PrivateKey
	pk.FromHex(os.Getenv("PRIVATE_KEY"))
	account, _ := aptos.NewAccountFromSigner(&pk)
	testnetClient, _ := aptos.NewNodeClient("https://api.testnet.aptoslabs.com/v1", 0)

	ccipAddress := aptos.AccountAddress{}
	_ = ccipAddress.ParseStringRelaxed("0xb23e6259f2a899fa0a78ef5d0a3853e226868f85c22f929e997e37faa65a4a5a")

	feeTokenAddress := aptos.AccountAddress{}
	_ = feeTokenAddress.ParseStringRelaxed("0xa")

	toAddress := common.LeftPadBytes(common.HexToAddress("0x90392A1E8A941098a3C75E0BDB172cFdE7E4f1f4").Bytes(), 32)

	extraArgs, _ := GetEVMExtraArgsV2(big.NewInt(1000000), false)

	opts := &bind.TransactOpts{Signer: account}

	ccip := cciprouter.Bind(ccipAddress, testnetClient)
	tx, err := ccip.Router.CCIPSend(opts, 16015286601757825753, toAddress, []byte("Hello, world!"), nil, nil, nil, feeTokenAddress, aptos.AccountZero, extraArgs)
	require.NoError(t, err)
	data, err := testnetClient.WaitForTransaction(tx.Hash)
	require.NoError(t, err)
	require.True(t, data.Success, "transaction failed", data.VmStatus)

	fmt.Println("CCIP Message sent in transaction:", tx.Hash)

	for i, event := range data.Events {
		fmt.Println("Event", i, event.Type)
		fmt.Printf("%+v\n", event.Data)
	}
}

func GetEVMExtraArgsV2(gasLimit *big.Int, allowOutOfOrder bool) ([]byte, error) {
	// see Client.sol.
	EVMV2Tag := hexutil.MustDecode("0x181dcf10")

	encodedArgs, err := utils.ABIEncode(`[{"type":"uint256"},{"type":"bool"}]`, gasLimit, allowOutOfOrder)
	if err != nil {
		return nil, err
	}

	return append(EVMV2Tag, encodedArgs...), nil
}
