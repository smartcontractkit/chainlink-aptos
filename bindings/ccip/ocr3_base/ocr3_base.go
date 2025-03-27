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
}

const FunctionInfo = `[{"package":"ccip","module":"ocr3_base","name":"deserialize_sequence_bytes","parameters":[{"name":"sequence_bytes","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"ocr3_base","name":"new","parameters":null},{"package":"ccip","module":"ocr3_base","name":"ocr_plugin_type_commit","parameters":null},{"package":"ccip","module":"ocr3_base","name":"ocr_plugin_type_execution","parameters":null}]`

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

type LatestConfigDetails struct {
	OcrConfig OCRConfig `move:"OCRConfig"`
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

type Ocr3Base struct {
	Ocr3BaseCaller
	Ocr3BaseTransactor
}

// View Functions

type Ocr3BaseCaller struct {
	*bind.BoundContract
}

// Entry Functions

type Ocr3BaseTransactor struct {
	*bind.BoundContract
}

// Other Functions

func (c Ocr3BaseCaller) EncodeNew() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new", nil, []string{}, []any{})
}

func (c Ocr3BaseCaller) EncodeOcrPluginTypeCommit() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ocr_plugin_type_commit", nil, []string{}, []any{})
}

func (c Ocr3BaseCaller) EncodeOcrPluginTypeExecution() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ocr_plugin_type_execution", nil, []string{}, []any{})
}

func (c Ocr3BaseCaller) EncodeDeserializeSequenceBytes(sequenceBytes []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("deserialize_sequence_bytes", nil, []string{
		"vector<u8>",
	}, []any{
		sequenceBytes,
	})
}
