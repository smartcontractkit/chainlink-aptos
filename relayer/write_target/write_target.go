package write_target

import (
	"context"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"

	aptosacc "github.com/smartcontractkit/chainlink-aptos/relayer/account"
	chain "github.com/smartcontractkit/chainlink-aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainwriter"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
	aptosconfig "github.com/smartcontractkit/chainlink-aptos/relayer/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/fees"
	aptosregistry "github.com/smartcontractkit/chainlink-aptos/relayer/monitroing/pb/data-feeds/on-chain/registry"
	"github.com/smartcontractkit/chainlink-aptos/relayer/write_target/types"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-evm/pkg/report/monitor"
	"github.com/smartcontractkit/chainlink-evm/pkg/report/pb/data-feeds/on-chain/registry"
	wt "github.com/smartcontractkit/chainlink-evm/pkg/report/pb/platform"
	"github.com/smartcontractkit/chainlink-evm/pkg/writetarget"
)

const version = "1.0.0"

type AptosConfig struct {
	Address string
}

// EVM Data-Feeds specific processor decodes writes as 'data-feeds.registry.FeedUpdated' messages + metrics
type dataFeedsProcessor struct {
	emitter monitor.ProtoEmitter
	metrics *registry.Metrics
}

func (p *dataFeedsProcessor) Process(ctx context.Context, m proto.Message, attrKVs ...any) error {
	// Switch on the type of the proto.Message
	switch msg := m.(type) {
	case *wt.WriteConfirmed:
		// TODO: fallthrough if not a write containing a DF report
		// https://smartcontract-it.atlassian.net/browse/NONEVM-818
		// Notice: we assume all writes are Data-Feeds (static schema) writes for now

		// Decode as an array of 'data-feeds.registry.FeedUpdated' messages
		updates, err := aptosregistry.DecodeAsFeedUpdated(msg)
		if err != nil {
			return fmt.Errorf("failed to decode as 'data-feeds.registry.FeedUpdated': %w", err)
		}
		// Emit the 'data-feeds.registry.FeedUpdated' messages
		for _, update := range updates {
			err = p.emitter.EmitWithLog(ctx, update, attrKVs...)
			if err != nil {
				return fmt.Errorf("failed to emit with log: %w", err)
			}
			// Process emit and derive metrics
			err = p.metrics.OnFeedUpdated(ctx, update, attrKVs...)
			if err != nil {
				return fmt.Errorf("failed to publish feed updated metrics: %w", err)
			}
		}
		return nil
	default:
		return nil // fallthrough
	}
}

func (c *dataFeedsProcessor) SetEmitter(e monitor.ProtoEmitter) {
	c.emitter = e
}

func NewAptosWriteTarget(ctx context.Context, chain chain.Chain, lggr logger.Logger) (capabilities.TargetCapability, error) {
	config := chain.Config()

	// TODO: generate ID based on chain selector (we're currently using Aptos Go SDK to get name for chain ID)
	// chainName, err := chainselectors.NameFromChainId(chain.ID().Uint64())

	// Construct the ID for the WT (e.g., "write_aptos-localnet@1.0.0")
	id, err := writetarget.NewWriteTargetID(aptosconfig.ChainFamilyName, config.NetworkName, config.ChainID, version)
	if err != nil {
		return nil, fmt.Errorf("failed to create write target ID: %+w", err)
	}

	// All subcomponents constructed by this WT will use the same logger
	lggr = logger.Named(lggr, id)

	client, err := chain.GetClient()
	if err != nil {
		return nil, err
	}

	// Set up a specific Beholder client for the Aptos WT
	beholder, err := writetarget.NewMonitor(lggr, types.DecodeAsFeedUpdated)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos WT monitor client: %+w", err)
	}

	// Initialize a reader to check whether a value was already transmitted on chain
	cr := chainreader.NewChainReader(lggr, client, chainreader.ChainReaderConfig{
		Modules: map[string]*chainreader.ChainReaderModule{
			"forwarder": {
				Functions: map[string]*chainreader.ChainReaderFunction{
					"getTransmissionState": {
						Name: "get_transmission_state",
						Params: []codec.AptosFunctionParam{
							{
								Name:     "Receiver",
								Type:     "address",
								Required: true,
							},
							{
								Name:     "WorkflowExecutionID",
								Type:     "vector<u8>",
								Required: true,
							},
							{
								Name:     "ReportID",
								Type:     "u16",
								Required: true,
							},
						},
					},
					"getTransmitter": {
						Name: "get_transmitter",
						Params: []codec.AptosFunctionParam{
							{
								Name:     "Receiver",
								Type:     "address",
								Required: true,
							},
							{
								Name:     "WorkflowExecutionID",
								Type:     "vector<u8>",
								Required: true,
							},
							{
								Name:     "ReportID",
								Type:     "u16",
								Required: true,
							},
						},
					},
				},
			},
		},
	})

	err = cr.Bind(ctx, []commontypes.BoundContract{{
		Address: config.Workflow.ForwarderAddress,
		Name:    "forwarder",
	}})
	if err != nil {
		return nil, err
	}

	cwConfig := chainwriter.ChainWriterConfig{
		Modules: map[string]*chainwriter.ChainWriterModule{
			"forwarder": {
				Functions: map[string]*chainwriter.ChainWriterFunction{
					"report": {
						PublicKey: config.Workflow.PublicKey,
						Params: []codec.AptosFunctionParam{
							{
								Name:     "Receiver",
								Type:     "address",
								Required: true,
							},
							{
								Name:     "RawReport",
								Type:     "vector<u8>", // report_context | metadata | report
								Required: true,
							},
							{
								Name:     "Signatures",
								Type:     "vector<vector<u8>>",
								Required: true,
							},
						},
					},
				},
			},
		},
		FeeStrategy: fees.Default,
	}

	fe := fees.NewFeeEstimator(client)
	cw := chainwriter.NewChainWriter(lggr, fe, chain.TxManager(), cwConfig)

	validate := func(request capabilities.CapabilityRequest) (string, error) {
		receiver, err := getReceiver(request)
		if err != nil {
			return "", err
		}
		address := aptos.AccountAddress{}
		if err = address.ParseStringRelaxed(receiver); err != nil {
			return "", fmt.Errorf("'%v' is not a valid Aptos address", receiver)
		}
		return receiver, nil
	}

	transmitter, err := getTransmitter(cwConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get transmitter: %+w", err)
	}

	// Construct the chain information from the config
	chainInfo := monitor.ChainInfo{
		ChainFamilyName: aptosconfig.ChainFamilyName, // static for this plugin
		ChainID:         config.ChainID,
		NetworkName:     config.NetworkName,
		NetworkNameFull: config.NetworkNameFull,
	}

	targetStrategy := NewAptosTargetStrategy(cr, cw, lggr, config.Workflow.ForwarderAddress)

	// Create the WT capability
	opts := writetarget.WriteTargetOpts{
		ID:     id,
		Logger: lggr,
		Config: *config.WriteTargetCap,
		// TODO: simplify by passing via ChainService.GetChainStatus fn
		ChainInfo:        chainInfo,
		Beholder:         beholder,
		ChainService:     chain,
		ContractReader:   cr,
		ChainWriter:      cw,
		ConfigValidateFn: validate,
		NodeAddress:      transmitter,
		ForwarderAddress: config.Workflow.ForwarderAddress,
		TargetStrategy:   targetStrategy,
	}
	return writetarget.NewWriteTarget(opts), nil
}

// getTransmitter sources the transmitter address from the CW config
func getTransmitter(cwConfig chainwriter.ChainWriterConfig) (string, error) {
	// Try to source the transmitter (e.g., c.cw.config.Functions["forwarder"].FromAddress)
	moduleConfig, ok := cwConfig.Modules[ContractName]
	if !ok {
		return "", fmt.Errorf("no such contract: %s", ContractName)
	}

	functionConfig, ok := moduleConfig.Functions[ContractMethodName_report]
	if !ok {
		return "", fmt.Errorf("no such method: %s", ContractMethodName_report)
	}

	// Notice: reusing logic from the TXM which sources the transmitter this way
	transmitter := functionConfig.FromAddress
	if transmitter == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		ed25519PublicKey, err := aptosacc.HexPublicKeyToEd25519PublicKey(functionConfig.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to convert public key: %+w", err)
		}
		acc := aptosacc.Ed25519PublicKeyToAccount(ed25519PublicKey)
		transmitter = acc.String()
	}
	return transmitter, nil
}

func getReceiver(request capabilities.CapabilityRequest) (string, error) {
	var aptosConfig AptosConfig
	err := request.Config.UnwrapTo(&aptosConfig)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap AptosConfig: %w", err)
	}
	return aptosConfig.Address, nil
}
