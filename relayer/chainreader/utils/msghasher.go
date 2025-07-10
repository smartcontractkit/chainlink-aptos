package utils

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Hasher implementation is copied from https://github.com/smartcontractkit/chainlink/pull/16576/files#diff-5abaaa7db8de3f4203e0daf104ab54b770d92dbf510346b7cb1ca13540eecb44
// With the following modifications:
// - GasLimit is parsed direclty from the message, no extraDataCoded dependency
// - onRamp address is to be provided by the caller

var (
	// const LEAF_DOMAIN_SEPARATOR: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
	leafDomainSeparator = [32]byte{}

	// see aptos_hash::keccak256(b"Any2AptosMessageHashV1") in calculate_metadata_hash
	any2AptosMessageHash = keccak256Fixed([]byte("Any2AptosMessageHashV1"))
)

type MessageHasherV1 struct {
	lggr logger.Logger
}

type any2AptosTokenTransfer struct {
	SourcePoolAddress []byte
	DestTokenAddress  [32]byte
	DestGasAmount     uint32
	ExtraData         []byte
	Amount            *big.Int
}

func NewMessageHasherV1(lggr logger.Logger) *MessageHasherV1 {
	return &MessageHasherV1{
		lggr: lggr,
	}
}

func (h *MessageHasherV1) Hash(ctx context.Context, report *ExecutionReport, onRampAddress []byte) ([32]byte, error) {
	rampTokenAmounts := make([]any2AptosTokenTransfer, len(report.Message.TokenAmounts))
	for i, rta := range report.Message.TokenAmounts {
		destTokenAddress := [32]byte(rta.DestTokenAddress)

		rampTokenAmounts[i] = any2AptosTokenTransfer{
			SourcePoolAddress: rta.SourcePoolAddress,
			DestTokenAddress:  destTokenAddress,
			DestGasAmount:     rta.DestGasAmount,
			ExtraData:         rta.ExtraData,
			Amount:            rta.Amount,
		}
	}

	metaDataHash, err := computeMetadataHash(
		report.SourceChainSelector,
		report.Message.Header.DestChainSelector,
		onRampAddress,
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("compute metadata hash: %w", err)
	}

	if len(report.Message.Header.MessageID) != 32 {
		return [32]byte{}, fmt.Errorf("invalid MessageID length: %d", len(report.Message.Header.MessageID))
	}

	var messageID [32]byte
	copy(messageID[:], report.Message.Header.MessageID)

	receiverAddress := [32]byte(report.Message.Receiver)

	msgHash, err := computeMessageDataHash(
		metaDataHash,
		messageID,
		receiverAddress,
		report.Message.Header.SequenceNumber,
		report.Message.GasLimit,
		report.Message.Header.Nonce,
		report.Message.Sender,
		report.Message.Data,
		rampTokenAmounts,
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("compute message hash: %w", err)
	}

	return msgHash, nil
}

func computeMessageDataHash(
	metadataHash [32]byte,
	messageID [32]byte,
	receiver [32]byte,
	sequenceNumber uint64,
	gasLimit *big.Int,
	nonce uint64,
	sender []byte,
	data []byte,
	tokenAmounts []any2AptosTokenTransfer,
) ([32]byte, error) {
	uint64Type, err := abi.NewType("uint64", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create uint64 ABI type: %w", err)
	}

	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create uint256 ABI type: %w", err)
	}

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create bytes32 ABI type: %w", err)
	}

	headerArgs := abi.Arguments{
		{Type: bytes32Type}, // messageID
		{Type: bytes32Type}, // receiver as bytes32
		{Type: uint64Type},  // sequenceNumber
		{Type: uint256Type}, // gasLimit
		{Type: uint64Type},  // nonce
	}
	headerEncoded, err := headerArgs.Pack(
		messageID,
		receiver,
		sequenceNumber,
		gasLimit,
		nonce,
	)
	if err != nil {
		return [32]byte{}, err
	}
	headerHash := crypto.Keccak256Hash(headerEncoded)

	senderHash := crypto.Keccak256Hash(sender)

	dataHash := crypto.Keccak256Hash(data)

	type tokenTuple struct {
		SourcePoolAddress []byte
		DestTokenAddress  [32]byte
		DestGasAmount     uint32
		ExtraData         []byte
		Amount            *big.Int
	}
	tokens := make([]tokenTuple, len(tokenAmounts))
	for i, token := range tokenAmounts {
		tokens[i] = tokenTuple{
			SourcePoolAddress: token.SourcePoolAddress,
			DestTokenAddress:  token.DestTokenAddress,
			DestGasAmount:     token.DestGasAmount,
			ExtraData:         token.ExtraData,
			Amount:            token.Amount,
		}
	}

	var tokenHashData []byte
	tokenCountBytes, err := encodeUint256(big.NewInt(int64(len(tokens))))
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to encode token count: %w", err)
	}
	tokenHashData = append(tokenHashData, tokenCountBytes...)
	for _, token := range tokens {
		tokenHashData = append(tokenHashData, encodeBytes(token.SourcePoolAddress)...)
		tokenHashData = append(tokenHashData, token.DestTokenAddress[:]...)
		tokenHashData = append(tokenHashData, encodeUint32(token.DestGasAmount)...)
		tokenHashData = append(tokenHashData, encodeBytes(token.ExtraData)...)
		tokenAmountBytes, err := encodeUint256(token.Amount)
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to encode token amount: %w", err)
		}
		tokenHashData = append(tokenHashData, tokenAmountBytes...)
	}
	tokenAmountsHash := crypto.Keccak256Hash(tokenHashData)

	finalArgs := abi.Arguments{
		{Type: bytes32Type}, // LEAF_DOMAIN_SEPARATOR
		{Type: bytes32Type}, // metadataHash
		{Type: bytes32Type}, // headerHash
		{Type: bytes32Type}, // senderHash
		{Type: bytes32Type}, // dataHash
		{Type: bytes32Type}, // tokenAmountsHash
	}

	finalEncoded, err := finalArgs.Pack(
		leafDomainSeparator,
		metadataHash,
		headerHash,
		senderHash,
		dataHash,
		tokenAmountsHash,
	)
	if err != nil {
		return [32]byte{}, err
	}

	return crypto.Keccak256Hash(finalEncoded), nil
}

func computeMetadataHash(
	sourceChainSelector uint64,
	destinationChainSelector uint64,
	onRamp []byte,
) ([32]byte, error) {
	uint64Type, err := abi.NewType("uint64", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create uint64 ABI type: %w", err)
	}

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create bytes32 ABI type: %w", err)
	}

	onRampHash := crypto.Keccak256Hash(onRamp)

	args := abi.Arguments{
		{Type: bytes32Type}, // ANY_2_APTOS_MESSAGE_HASH
		{Type: uint64Type},  // sourceChainSelector
		{Type: uint64Type},  // destinationChainSelector (i_chainSelector)
		{Type: bytes32Type}, // onRamp
	}

	encoded, err := args.Pack(
		any2AptosMessageHash,
		sourceChainSelector,
		destinationChainSelector,
		onRampHash,
	)
	if err != nil {
		return [32]byte{}, err
	}

	metadataHash := crypto.Keccak256Hash(encoded)
	return metadataHash, nil
}

func encodeUint256(n *big.Int) ([]byte, error) {
	if n == nil {
		return nil, fmt.Errorf("encodeUint256: nil big.Int value")
	}
	return common.LeftPadBytes(n.Bytes(), 32), nil
}

func encodeUint32(n uint32) []byte {
	return common.LeftPadBytes(new(big.Int).SetUint64(uint64(n)).Bytes(), 32)
}

func encodeBytes(b []byte) []byte {
	encodedLength := common.LeftPadBytes(big.NewInt(int64(len(b))).Bytes(), 32)
	padLen := (32 - (len(b) % 32)) % 32
	result := make([]byte, 32+len(b)+padLen)
	copy(result[:32], encodedLength)
	copy(result[32:], b)
	return result
}

func keccak256Fixed(in []byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	// Note this Keccak256 cannot error https://github.com/golang/crypto/blob/master/sha3/sha3.go#L126
	// if we start supporting hashing algos which do, we can change this API to include an error.
	hash.Write(in)
	var h [32]byte
	copy(h[:], hash.Sum(nil))
	return h
}
