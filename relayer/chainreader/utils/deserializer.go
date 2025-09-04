package utils

import (
	"fmt"
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
)

type RampMessageHeader struct {
	MessageID           []byte
	SourceChainSelector uint64
	DestChainSelector   uint64
	SequenceNumber      uint64
	Nonce               uint64
}

type Any2AptosTokenTransfer struct {
	SourcePoolAddress []byte
	DestTokenAddress  aptos.AccountAddress
	DestGasAmount     uint32
	ExtraData         []byte
	Amount            *big.Int
}

type Any2AptosRampMessage struct {
	Header       RampMessageHeader
	Sender       []byte
	Data         []byte
	Receiver     aptos.AccountAddress
	GasLimit     *big.Int
	TokenAmounts []Any2AptosTokenTransfer
}

type ExecutionReport struct {
	SourceChainSelector uint64
	Message             Any2AptosRampMessage
	OffchainTokenData   [][]byte
	Proofs              [][]byte
}

type ConfigSet struct {
	OcrPluginType byte
	ConfigDigest  []byte
	Signers       [][]byte
	Transmitters  []aptos.AccountAddress
	BigF          byte
}

type SourceChainConfigSet struct {
	SourceChainSelector uint64
	SourceChainConfig   SourceChainConfig
}

type SourceChainConfig struct {
	Router                    string
	IsEnabled                 bool
	MinSeqNr                  uint64
	IsRMNVerificationDisabled bool
	OnRamp                    []byte
}

func DeserializeExecutionReport(data []byte) (*ExecutionReport, error) {
	deserializer := bcs.NewDeserializer(data)

	// 1. Read source_chain_selector (u64)
	sourceChainSelector := deserializer.U64()

	// 2. Read message header
	messageID := make([]byte, 32)
	deserializer.ReadFixedBytesInto(messageID)

	headerSourceChain := deserializer.U64()
	destChainSelector := deserializer.U64()
	sequenceNumber := deserializer.U64()
	nonce := deserializer.U64()

	if sourceChainSelector != headerSourceChain {
		return nil, fmt.Errorf("source chain selector mismatch: %d != %d", sourceChainSelector, headerSourceChain)
	}

	header := RampMessageHeader{
		MessageID:           messageID,
		SourceChainSelector: headerSourceChain,
		DestChainSelector:   destChainSelector,
		SequenceNumber:      sequenceNumber,
		Nonce:               nonce,
	}

	// 3. Read sender (vector<u8>)
	sender := deserializer.ReadBytes()

	// 4. Read data (vector<u8>)
	msgData := deserializer.ReadBytes()

	// 5. Read receiver (address)
	receiver := aptos.AccountAddress{}
	deserializer.Struct(&receiver)

	// 6. Read gas_limit (u256)
	gasLimit := deserializer.U256()

	// 7. Read token_amounts vector
	tokenAmountsLen := deserializer.Uleb128()
	tokenAmounts := make([]Any2AptosTokenTransfer, tokenAmountsLen)

	for i := uint32(0); i < tokenAmountsLen; i++ {
		sourcePoolAddr := deserializer.ReadBytes()

		destToken := aptos.AccountAddress{}
		deserializer.Struct(&destToken)

		destGas := deserializer.U32()
		extraData := deserializer.ReadBytes()
		amount := deserializer.U256()

		tokenAmounts[i] = Any2AptosTokenTransfer{
			SourcePoolAddress: sourcePoolAddr,
			DestTokenAddress:  destToken,
			DestGasAmount:     destGas,
			ExtraData:         extraData,
			Amount:            &amount,
		}
	}

	message := Any2AptosRampMessage{
		Header:       header,
		Sender:       sender,
		Data:         msgData,
		Receiver:     receiver,
		GasLimit:     &gasLimit,
		TokenAmounts: tokenAmounts,
	}

	// 8. Read offchain_token_data (vector<vector<u8>>)
	offchainDataLen := deserializer.Uleb128()
	offchainData := make([][]byte, offchainDataLen)

	for i := uint32(0); i < offchainDataLen; i++ {
		offchainData[i] = deserializer.ReadBytes()
	}

	// 9. Read proofs (vector<vector<u8>>)
	proofsLen := deserializer.Uleb128()
	proofs := make([][]byte, proofsLen)

	for i := uint32(0); i < proofsLen; i++ {
		proofs[i] = deserializer.ReadFixedBytes(32)
	}

	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize execution report: %w", err)
	}

	return &ExecutionReport{
		SourceChainSelector: sourceChainSelector,
		Message:             message,
		OffchainTokenData:   offchainData,
		Proofs:              proofs,
	}, nil
}
