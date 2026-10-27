package utils

import (
	"math"
	"math/big"
	"runtime"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validWith returns the serialized bytes of a valid report with optional modifications
// applied by the modifier function.
func validWith(modifier func(report *rawSerializedReport)) []byte {
	report := &rawSerializedReport{
		sourceChainSelector:       1,
		messageId:                 common.HexToHash("0x2"),
		headerSourceChainSelector: 1,
		headerDestChainSelector:   3,
		headerSequenceNumber:      4,
		headerNonce:               5,
		senderLength:              1,
		sender:                    []byte{0x45},
		dataLength:                1,
		data:                      []byte{0x67},
		receiver:                  common.HexToHash("0x8"),
		gasLimit:                  big.NewInt(1),
		tokenAmountsLength:        1,
		tokenAmounts: []rawTokenAmount{{
			sourcePoolAddressLength: 2,
			sourcePoolAddress:       []byte{0x11, 0x22},
			destToken:               common.HexToHash("0x7777"),
			destGas:                 0,
			extraDataLength:         0,
			extraData:               nil,
			amount:                  big.NewInt(99999),
		}},
		offchainTokenDataLength: 2,
		offchainTokenData: []rawVec8{
			{
				dataLength: 0,
				data:       []byte{},
			}, {
				dataLength: 2,
				data:       []byte{0x33, 0x44},
			},
		},
		proofsLength: 1,
		proofs:       [][]byte{common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").Bytes()},
	}
	if modifier != nil {
		modifier(report)
	}
	return serializeUnchecked(*report)
}

func TestDeserializeExecutionReport(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *ExecutionReport
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid report",
			data: common.FromHex("0xd91ad9c94fba41de8869e580deb6dbc08e84fb41431d41d04f8849ed00be4a070dca7c34e2f78ecdd91ad9c94fba41de15a9c133ee53500a0300000000000000000000000000000014e30b40bfb1baeed9e4c62f145be85eb3d19ae932184920616d206120746573742063636970206d6573736167654010af5717948371a0b649a59530f8e80e0e1247e015f05f1f3e09c715288dd040420f00000000000000000000000000000000000000000000000000000000000114bd10ffa3815c010d5cf7d38815a0eaabc959eb84a1b6cf2e878987deb2624f9a122297abf6332d45b48c4df6fc3ea705f810980fa08601002000000000000000000000000000000000000000000000000000000000000000120000c16ff2862300000000000000000000000000000000000000000000000000010000"),
			want: &ExecutionReport{
				SourceChainSelector: 16015286601757825753,
				Message: Any2AptosRampMessage{
					Header: RampMessageHeader{
						MessageID:           common.FromHex("0x8869e580deb6dbc08e84fb41431d41d04f8849ed00be4a070dca7c34e2f78ecd"),
						SourceChainSelector: 16015286601757825753,
						DestChainSelector:   743186221051783445,
						SequenceNumber:      3,
						Nonce:               0,
					},
					Sender:   common.FromHex("0xe30b40bfb1baeed9e4c62f145be85eb3d19ae932"),
					Data:     []byte("I am a test ccip message"),
					Receiver: mustParseAddress("0x4010af5717948371a0b649a59530f8e80e0e1247e015f05f1f3e09c715288dd0"),
					GasLimit: big.NewInt(1000000),
					TokenAmounts: []Any2AptosTokenTransfer{
						{
							SourcePoolAddress: common.FromHex("0xbd10ffa3815c010d5cf7d38815a0eaabc959eb84"),
							DestTokenAddress:  mustParseAddress("0xa1b6cf2e878987deb2624f9a122297abf6332d45b48c4df6fc3ea705f810980f"),
							DestGasAmount:     100000,
							ExtraData:         common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000012"),
							Amount:            big.NewInt(10000000000000000),
						},
					},
				},
				OffchainTokenData: [][]byte{{}},
				Proofs:            nil,
			},
			wantErr: assert.NoError,
		}, {
			name: "valid raw",
			data: validWith(nil),
			want: &ExecutionReport{
				SourceChainSelector: 1,
				Message: Any2AptosRampMessage{
					Header: RampMessageHeader{
						MessageID:           common.HexToHash("0x2").Bytes(),
						SourceChainSelector: 1,
						DestChainSelector:   3,
						SequenceNumber:      4,
						Nonce:               5,
					},
					Sender:   []byte{0x45},
					Data:     []byte{0x67},
					Receiver: mustParseAddress("0x8"),
					GasLimit: big.NewInt(1),
					TokenAmounts: []Any2AptosTokenTransfer{{
						SourcePoolAddress: []byte{0x11, 0x22},
						DestTokenAddress:  mustParseAddress("0x7777"),
						DestGasAmount:     0,
						ExtraData:         []byte{},
						Amount:            big.NewInt(99999),
					}},
				},
				OffchainTokenData: [][]byte{[]byte{}, []byte{0x33, 0x44}},
				Proofs:            [][]byte{common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").Bytes()},
			},
			wantErr: assert.NoError,
		}, {
			name: "invalid sender length",
			data: validWith(func(report *rawSerializedReport) {
				report.senderLength = math.MaxUint32
			}),
			want:    nil,
			wantErr: assert.Error,
		}, {
			name: "invalid data length",
			data: validWith(func(report *rawSerializedReport) {
				report.dataLength = math.MaxUint32
			}),
			want:    nil,
			wantErr: assert.Error,
		}, {
			name: "invalid token amounts length",
			data: validWith(func(report *rawSerializedReport) {
				report.tokenAmountsLength = math.MaxUint32
			}),
			want:    nil,
			wantErr: assert.Error,
		}, {
			name: "invalid offchain token data length",
			data: validWith(func(report *rawSerializedReport) {
				report.offchainTokenDataLength = math.MaxUint32
			}),
			want:    nil,
			wantErr: assert.Error,
		}, {
			name: "invalid proofs length",
			data: validWith(func(report *rawSerializedReport) {
				report.proofsLength = math.MaxUint32
			}),
			want:    nil,
			wantErr: assert.Error,
		}, {
			name: "invalid trailing bytes",
			data: append(validWith(nil), 0x00, 0x01, 0x02), // Add extra bytes at the end
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				return assert.ErrorContains(t, err, "trailing bytes")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeExecutionReport(tt.data)

			if !tt.wantErr(t, err, "DeserializeExecutionReport()") {
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// measureAllocGrowth runs fn and returns the total number of bytes allocated while it ran.
// TotalAlloc is cumulative and unaffected by GC, so a large transient allocation shows up
// in full even if it is unreachable by the time fn returns.
func measureAllocGrowth(t *testing.T, fn func()) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestReadBoundedBytes(t *testing.T) {
	t.Run("reads a vector that fits the input", func(t *testing.T) {
		d := bcs.NewDeserializer([]byte{0x02, 0xAA, 0xBB})
		got, err := readBoundedBytes(d, "field")
		require.NoError(t, err)
		assert.Equal(t, []byte{0xAA, 0xBB}, got)
		require.NoError(t, d.Error())
	})

	t.Run("rejects a length the input cannot satisfy", func(t *testing.T) {
		d := bcs.NewDeserializer([]byte{0x03, 0xAA, 0xBB})
		_, err := readBoundedBytes(d, "field")
		require.ErrorContains(t, err, "declared length 3 exceeds 2 remaining bytes")
	})

	t.Run("rejects a huge length without allocating it", func(t *testing.T) {
		// ULEB128 encoding of math.MaxUint32, with nothing behind it.
		d := bcs.NewDeserializer([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F})
		var err error
		growth := measureAllocGrowth(t, func() {
			_, err = readBoundedBytes(d, "field")
		})
		require.ErrorContains(t, err, "declared length 4294967295 exceeds 0 remaining bytes")
		assert.Less(t, growth, uint64(1<<20), "forged length must be rejected before allocating")
	})
}

func TestDeserializeExecutionReport_ForgedLengthsDoNotAllocate(t *testing.T) {
	tests := []struct {
		name    string
		forge   func(report *rawSerializedReport)
		wantErr string
	}{
		{
			name: "sender",
			forge: func(report *rawSerializedReport) {
				report.senderLength = math.MaxUint32
			},
			wantErr: "failed to deserialize sender: declared length 4294967295 exceeds",
		}, {
			name: "data",
			forge: func(report *rawSerializedReport) {
				report.dataLength = math.MaxUint32
			},
			wantErr: "failed to deserialize data: declared length 4294967295 exceeds",
		}, {
			name: "tokenAmounts[0].sourcePoolAddress",
			forge: func(report *rawSerializedReport) {
				report.tokenAmounts[0].sourcePoolAddressLength = math.MaxUint32
			},
			wantErr: "failed to deserialize tokenAmounts[0].sourcePoolAddress: declared length 4294967295 exceeds",
		}, {
			name: "tokenAmounts[0].extraData",
			forge: func(report *rawSerializedReport) {
				report.tokenAmounts[0].extraDataLength = math.MaxUint32
			},
			wantErr: "failed to deserialize tokenAmounts[0].extraData: declared length 4294967295 exceeds",
		}, {
			name: "offchainTokenData[1]",
			forge: func(report *rawSerializedReport) {
				report.offchainTokenData[1].dataLength = math.MaxUint32
			},
			wantErr: "failed to deserialize offchainTokenData[1]: declared length 4294967295 exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := validWith(tt.forge)
			var got *ExecutionReport
			var err error
			growth := measureAllocGrowth(t, func() {
				got, err = DeserializeExecutionReport(data)
			})
			require.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, got)
			// A declared length of MaxUint32 is a ~4 GiB request the input cannot
			// satisfy; it must be refused before the bytes are allocated.
			assert.Less(t, growth, uint64(1<<20), "forged length must be rejected before allocating")
		})
	}
}

func mustParseAddress(address string) aptos.AccountAddress {
	addr := aptos.AccountAddress{}
	if err := addr.ParseStringRelaxed(address); err != nil {
		panic(err)
	}

	return addr
}

type rawTokenAmount struct {
	sourcePoolAddressLength uint32
	sourcePoolAddress       []byte
	destToken               [32]byte
	destGas                 uint32
	extraDataLength         uint32
	extraData               []byte
	amount                  *big.Int
}

type rawVec8 struct {
	dataLength uint32
	data       []byte
}

type rawSerializedReport struct {
	sourceChainSelector uint64
	// Header
	messageId                 [32]byte
	headerSourceChainSelector uint64
	headerDestChainSelector   uint64
	headerSequenceNumber      uint64
	headerNonce               uint64

	senderLength uint32
	sender       []byte
	dataLength   uint32
	data         []byte
	receiver     [32]byte
	gasLimit     *big.Int

	// Token Amounts
	tokenAmountsLength uint32
	tokenAmounts       []rawTokenAmount

	offchainTokenDataLength uint32
	offchainTokenData       []rawVec8

	proofsLength uint32
	proofs       [][]byte
}

// serialized a report without any guards - can be used to create an invalid serialized report
func serializeUnchecked(report rawSerializedReport) []byte {
	ser := bcs.Serializer{}
	ser.U64(report.sourceChainSelector)

	ser.FixedBytes(report.messageId[:])
	ser.U64(report.headerSourceChainSelector)
	ser.U64(report.headerDestChainSelector)
	ser.U64(report.headerSequenceNumber)
	ser.U64(report.headerNonce)

	ser.Uleb128(report.senderLength)
	ser.FixedBytes(report.sender)
	ser.Uleb128(report.dataLength)
	ser.FixedBytes(report.data)
	ser.FixedBytes(report.receiver[:])
	ser.U256(*report.gasLimit)

	ser.Uleb128(report.tokenAmountsLength)
	for _, tokenAmount := range report.tokenAmounts {
		ser.Uleb128(tokenAmount.sourcePoolAddressLength)
		ser.FixedBytes(tokenAmount.sourcePoolAddress)
		ser.FixedBytes(tokenAmount.destToken[:])
		ser.U32(tokenAmount.destGas)
		ser.Uleb128(tokenAmount.extraDataLength)
		ser.FixedBytes(tokenAmount.extraData)
		ser.U256(*tokenAmount.amount)
	}

	ser.Uleb128(report.offchainTokenDataLength)
	for _, vec8 := range report.offchainTokenData {
		ser.Uleb128(vec8.dataLength)
		ser.FixedBytes(vec8.data)
	}

	ser.Uleb128(report.proofsLength)
	for _, proof := range report.proofs {
		ser.FixedBytes(proof)
	}

	return ser.ToBytes()
}
