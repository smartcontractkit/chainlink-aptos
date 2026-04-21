// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mock_forwarder

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

var (
	_ = aptos.AccountAddress{}
	_ = api.PendingTransaction{}
	_ = big.NewInt
	_ = bind.NewBoundContract
	_ = codec.DecodeAptosJsonValue
)

type MockForwarderInterface interface {
	Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	Report(opts *bind.TransactOpts, receiver aptos.AccountAddress, rawReport []byte, Signatures [][]byte) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MockForwarderEncoder
}

type MockForwarderEncoder interface {
	Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Report(receiver aptos.AccountAddress, rawReport []byte, Signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"platform_mock","module":"mock_forwarder","name":"initialize","parameters":null},{"package":"platform_mock","module":"mock_forwarder","name":"report","parameters":[{"name":"receiver","type":"address"},{"name":"raw_report","type":"vector\u003cu8\u003e"},{"name":"_signatures","type":"vector\u003cvector\u003cu8\u003e\u003e"}]}]`

func NewMockForwarder(address aptos.AccountAddress, client aptos.AptosRpcClient) MockForwarderInterface {
	contract := bind.NewBoundContract(address, "platform_mock", "mock_forwarder", client)
	return MockForwarderContract{
		BoundContract:        contract,
		mockForwarderEncoder: mockForwarderEncoder{BoundContract: contract},
	}
}

// Structs

type ReportProcessed struct {
	Receiver     aptos.AccountAddress `move:"address"`
	RawReportLen uint64               `move:"u64"`
}

type State struct {
	Owner aptos.AccountAddress `move:"address"`
}

type MockForwarderContract struct {
	*bind.BoundContract
	mockForwarderEncoder
}

var _ MockForwarderInterface = MockForwarderContract{}

func (c MockForwarderContract) Encoder() MockForwarderEncoder {
	return c.mockForwarderEncoder
}

// View Functions

// Entry Functions

func (c MockForwarderContract) Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mockForwarderEncoder.Initialize()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MockForwarderContract) Report(opts *bind.TransactOpts, receiver aptos.AccountAddress, rawReport []byte, Signatures [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mockForwarderEncoder.Report(receiver, rawReport, Signatures)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type mockForwarderEncoder struct {
	*bind.BoundContract
}

func (c mockForwarderEncoder) Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{}, []any{})
}

func (c mockForwarderEncoder) Report(receiver aptos.AccountAddress, rawReport []byte, Signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("report", nil, []string{
		"address",
		"vector<u8>",
		"vector<vector<u8>>",
	}, []any{
		receiver,
		rawReport,
		Signatures,
	})
}
