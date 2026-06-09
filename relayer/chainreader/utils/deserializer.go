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
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize sourceChainSelector: %w", err)
	}

	// 2. Read message header
	messageID := make([]byte, 32)
	deserializer.ReadFixedBytesInto(messageID)
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize messageID: %w", err)
	}

	headerSourceChain := deserializer.U64()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize header.sourceChainSelector: %w", err)
	}
	destChainSelector := deserializer.U64()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize header.destChainSelector: %w", err)
	}
	sequenceNumber := deserializer.U64()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize header.sequenceNumber: %w", err)
	}
	nonce := deserializer.U64()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize header.nonce: %w", err)
	}

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
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize sender: %w", err)
	}

	// 4. Read data (vector<u8>)
	msgData := deserializer.ReadBytes()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize data: %w", err)
	}

	// 5. Read receiver (address)
	receiver := aptos.AccountAddress{}
	deserializer.Struct(&receiver)
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize receiver: %w", err)
	}

	// 6. Read gas_limit (u256)
	gasLimit := deserializer.U256()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize gasLimit: %w", err)
	}

	// 7. Read token_amounts vector
	tokenAmountsLen := deserializer.Uleb128()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize tokenAmounts length: %w", err)
	}
	var tokenAmounts []Any2AptosTokenTransfer

	for i := uint32(0); i < tokenAmountsLen; i++ {
		sourcePoolAddr := deserializer.ReadBytes()
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("failed to deserialize tokenAmounts[%d].sourcePoolAddress: %w", i, err)
		}

		destToken := aptos.AccountAddress{}
		deserializer.Struct(&destToken)
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("failed to deserialize tokenAmounts[%d].destToken: %w", i, err)
		}

		destGas := deserializer.U32()
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("failed to deserialize tokenAmounts[%d].destGas: %w", i, err)
		}
		extraData := deserializer.ReadBytes()
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("failed to deserialize tokenAmounts[%d].extraData: %w", i, err)
		}
		amount := deserializer.U256()
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("failed to deserialize tokenAmounts[%d].amount: %w", i, err)
		}

		tokenAmounts = append(tokenAmounts, Any2AptosTokenTransfer{
			SourcePoolAddress: sourcePoolAddr,
			DestTokenAddress:  destToken,
			DestGasAmount:     destGas,
			ExtraData:         extraData,
			Amount:            &amount,
		})
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
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize offchainTokenData length: %w", err)
	}
	var offchainData [][]byte

	for i := uint32(0); i < offchainDataLen; i++ {
		data := deserializer.ReadBytes()
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("failed to deserialize offchainTokenData[%d]: %w", i, err)
		}
		offchainData = append(offchainData, data)
	}

	// 9. Read proofs (vector<vector<u8>>)
	proofsLen := deserializer.Uleb128()
	if err := deserializer.Error(); err != nil {
		return nil, fmt.Errorf("failed to deserialize proofs length: %w", err)
	}
	var proofs [][]byte

	for i := uint32(0); i < proofsLen; i++ {
		data := deserializer.ReadFixedBytes(32)
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("failed to deserialize proofs[%d]: %w", i, err)
		}
		proofs = append(proofs, data)
	}

	trailingBytes := deserializer.Remaining()
	if trailingBytes > 0 {
		return nil, fmt.Errorf("failed to deserialize execution report, trailing bytes remaining: %d", trailingBytes)
	}

	return &ExecutionReport{
		SourceChainSelector: sourceChainSelector,
		Message:             message,
		OffchainTokenData:   offchainData,
		Proofs:              proofs,
	}, nil
}
