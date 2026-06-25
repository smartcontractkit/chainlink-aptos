package adapters

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	deployops "github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/sequences"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/internal"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation"
)

func (a *AptosAdapter) SetOCR3Config() *cldf_ops.Sequence[deployops.SetOCR3ConfigInput, sequences.OnChainOutput, cldf_chain.BlockChains] {
	return SetOCR3Config
}

var SetOCR3Config = cldf_ops.NewSequence(
	"aptos/sequences/ccip/tooling-api/set-ocr3-config",
	semver.MustParse("1.6.0"),
	"Set OCR3 Config on Aptos chains",
	func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, input deployops.SetOCR3ConfigInput) (sequences.OnChainOutput, error) {
		chainSelector := input.ChainSelector
		chain := chains.AptosChains()[chainSelector]

		ccipBytes, err := getCCIPAccountBytes(input.Datastore, chainSelector)
		if err != nil {
			return sequences.OnChainOutput{}, fmt.Errorf("get ccip address: %w", err)
		}
		deps := buildAptosDeps(chain, chainSelector, ccipBytes)

		var result sequences.OnChainOutput
		for pluginType, cfg := range input.Configs {
			report, err := cldf_ops.ExecuteOperation(b, operation.SetOcr3ConfigOp, deps, operation.SetOcr3ConfigInput{
				OcrPluginType: uint8(pluginType),
				OCRConfigArgs: intoOCRArgs(cfg),
			})
			if err != nil {
				return sequences.OnChainOutput{}, fmt.Errorf("set ocr3 config for plugin %d: %w", pluginType, err)
			}
			appendBatchOp(&result, chainSelector, []mcmstypes.Transaction{report.Output})
		}

		return result, nil
	},
)

func intoOCRArgs(cfg deployops.OCR3ConfigArgs) internal.MultiOCR3BaseOCRConfigArgsAptos {
	return internal.MultiOCR3BaseOCRConfigArgsAptos{
		ConfigDigest:                   cfg.ConfigDigest,
		OcrPluginType:                  uint8(cfg.PluginType),
		F:                              cfg.F,
		IsSignatureVerificationEnabled: cfg.IsSignatureVerificationEnabled,
		Signers:                        cfg.Signers,
		Transmitters:                   cfg.Transmitters,
	}
}
