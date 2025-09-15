// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_ocr3_base

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

type Ocr3BaseInterface interface {

	// Encoder returns the encoder implementation of this module.
	Encoder() Ocr3BaseEncoder
}

type Ocr3BaseEncoder interface {
	New() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	OcrPluginTypeCommit() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	OcrPluginTypeExecution() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DeserializeSequenceBytes(sequenceBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HashReport(report []byte, configDigest []byte, sequenceBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_offramp","module":"ocr3_base","name":"deserialize_sequence_bytes","parameters":[{"name":"sequence_bytes","type":"vector\u003cu8\u003e"}]},{"package":"ccip_offramp","module":"ocr3_base","name":"hash_report","parameters":[{"name":"report","type":"vector\u003cu8\u003e"},{"name":"config_digest","type":"vector\u003cu8\u003e"},{"name":"sequence_bytes","type":"vector\u003cu8\u003e"}]},{"package":"ccip_offramp","module":"ocr3_base","name":"new","parameters":null},{"package":"ccip_offramp","module":"ocr3_base","name":"ocr_plugin_type_commit","parameters":null},{"package":"ccip_offramp","module":"ocr3_base","name":"ocr_plugin_type_execution","parameters":null}]`

func NewOcr3Base(address aptos.AccountAddress, client aptos.AptosRpcClient) Ocr3BaseInterface {
	contract := bind.NewBoundContract(address, "ccip_offramp", "ocr3_base", client)
	return Ocr3BaseContract{
		BoundContract:   contract,
		ocr3BaseEncoder: ocr3BaseEncoder{BoundContract: contract},
	}
}

// Constants
const (
	MAX_NUM_ORACLES                   uint64 = 256
	OCR_PLUGIN_TYPE_COMMIT            byte   = 0
	OCR_PLUGIN_TYPE_EXECUTION         byte   = 1
	E_BIG_F_MUST_BE_POSITIVE          uint64 = 1
	E_STATIC_CONFIG_CANNOT_BE_CHANGED uint64 = 2
	E_TOO_MANY_SIGNERS                uint64 = 3
	E_BIG_F_TOO_HIGH                  uint64 = 4
	E_TOO_MANY_TRANSMITTERS           uint64 = 5
	E_NO_TRANSMITTERS                 uint64 = 6
	E_REPEATED_SIGNERS                uint64 = 7
	E_REPEATED_TRANSMITTERS           uint64 = 8
	E_FORKED_CHAIN                    uint64 = 9
	E_CONFIG_DIGEST_MISMATCH          uint64 = 10
	E_UNAUTHORIZED_TRANSMITTER        uint64 = 11
	E_WRONG_NUMBER_OF_SIGNATURES      uint64 = 12
	E_COULD_NOT_VALIDATE_SIGNER_KEY   uint64 = 13
	E_INVALID_REPORT_CONTEXT_LENGTH   uint64 = 14
	E_INVALID_CONFIG_DIGEST_LENGTH    uint64 = 15
	E_INVALID_SEQUENCE_LENGTH         uint64 = 16
	E_UNAUTHORIZED_SIGNER             uint64 = 17
	E_NON_UNIQUE_SIGNATURES           uint64 = 18
	E_INVALID_SIGNATURE               uint64 = 19
	E_ZERO_ADDRESS_NOT_ALLOWED        uint64 = 20
	E_INVALID_SIGNATURE_LENGTH        uint64 = 21
)

// Structs

type ConfigInfo struct {
	ConfigDigest                   []byte `move:"vector<u8>"`
	BigF                           byte   `move:"u8"`
	N                              byte   `move:"u8"`
	IsSignatureVerificationEnabled bool   `move:"bool"`
}

type OCRConfig struct {
	ConfigInfo   ConfigInfo             `move:"ConfigInfo"`
	Signers      [][]byte               `move:"vector<vector<u8>>"`
	Transmitters []aptos.AccountAddress `move:"vector<address>"`
}

type Oracle struct {
	Index byte `move:"u8"`
	Role  byte `move:"u8"`
}

type OCR3BaseState struct {
	ChainId byte `move:"u8"`
}

type ConfigSet struct {
	OcrPluginType byte                   `move:"u8"`
	ConfigDigest  []byte                 `move:"vector<u8>"`
	Signers       [][]byte               `move:"vector<vector<u8>>"`
	Transmitters  []aptos.AccountAddress `move:"vector<address>"`
	BigF          byte                   `move:"u8"`
}

type Transmitted struct {
	OcrPluginType  byte   `move:"u8"`
	ConfigDigest   []byte `move:"vector<u8>"`
	SequenceNumber uint64 `move:"u64"`
}

type Ocr3BaseContract struct {
	*bind.BoundContract
	ocr3BaseEncoder
}

var _ Ocr3BaseInterface = Ocr3BaseContract{}

func (c Ocr3BaseContract) Encoder() Ocr3BaseEncoder {
	return c.ocr3BaseEncoder
}

// View Functions

// Entry Functions

// Encoder
type ocr3BaseEncoder struct {
	*bind.BoundContract
}

func (c ocr3BaseEncoder) New() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new", nil, []string{}, []any{})
}

func (c ocr3BaseEncoder) OcrPluginTypeCommit() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ocr_plugin_type_commit", nil, []string{}, []any{})
}

func (c ocr3BaseEncoder) OcrPluginTypeExecution() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ocr_plugin_type_execution", nil, []string{}, []any{})
}

func (c ocr3BaseEncoder) DeserializeSequenceBytes(sequenceBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("deserialize_sequence_bytes", nil, []string{
		"vector<u8>",
	}, []any{
		sequenceBytes,
	})
}

func (c ocr3BaseEncoder) HashReport(report []byte, configDigest []byte, sequenceBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("hash_report", nil, []string{
		"vector<u8>",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		report,
		configDigest,
		sequenceBytes,
	})
}
