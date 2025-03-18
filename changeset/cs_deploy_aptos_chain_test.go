package changeset

import (
	"testing"

	"github.com/smartcontractkit/chainlink/deployment"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestCsDeployAptosChainImp_VerifyPreconditions(t *testing.T) {
	tests := []struct {
		name      string
		env       deployment.Environment
		config    DeployAptosChainConfig
		wantState map[uint64]AptosCCIPChainState
		wantErrRe string
		wantErr   bool
	}{
		{
			name: "success - valid config and state",
			env: deployment.Environment{
				Name:   "test",
				Logger: logger.Test(t),
				AptosChains: map[uint64]deployment.AptosChain{
					743186221051783445:  {},
					4457093679053095497: {},
				},
				ExistingAddresses: getTestAddressBook(
					map[uint64]map[string]deployment.TypeAndVersion{
						4457093679053095497: {
							mockMCMSAddress: {Type: AptosMCMSType},
						},
						743186221051783445: {
							mockMCMSAddress: {Type: AptosMCMSType},
						},
					},
				),
			},
			config: DeployAptosChainConfig{
				ContractParamsPerChain: map[uint64]ChainContractParams{
					4457093679053095497: getMockChainContractParams(t, 4457093679053095497),
					743186221051783445:  getMockChainContractParams(t, 743186221051783445),
				},
			},
			wantState: map[uint64]AptosCCIPChainState{
				743186221051783445: {
					AptosMCMSObjAddr: mustParseAddress(t, mockMCMSAddress),
				},
				4457093679053095497: {
					AptosMCMSObjAddr: mustParseAddress(t, mockMCMSAddress),
				},
			},
			wantErr: false,
		},
		{
			name: "error - chain has no env",
			env: deployment.Environment{
				Name:   "test",
				Logger: logger.Test(t),
				AptosChains: map[uint64]deployment.AptosChain{
					4457093679053095497: {},
				},
				ExistingAddresses: getTestAddressBook(
					map[uint64]map[string]deployment.TypeAndVersion{
						4457093679053095497: {
							mockMCMSAddress: {Type: AptosMCMSType},
						},
						743186221051783445: {
							mockMCMSAddress: {Type: AptosMCMSType},
						},
					},
				),
			},
			config: DeployAptosChainConfig{
				ContractParamsPerChain: map[uint64]ChainContractParams{
					4457093679053095497: getMockChainContractParams(t, 4457093679053095497),
					743186221051783445:  getMockChainContractParams(t, 743186221051783445),
				},
			},
			wantErrRe: `env not found for chains: \[743186221051783445\]`,
			wantErr:   true,
		},
		{
			name: "error - invalid config - chainSelector",
			env: deployment.Environment{
				Name:              "test",
				Logger:            logger.Test(t),
				ExistingAddresses: deployment.NewMemoryAddressBook(),
				AptosChains:       map[uint64]deployment.AptosChain{},
			},
			config: DeployAptosChainConfig{
				ContractParamsPerChain: map[uint64]ChainContractParams{
					1: {},
				},
			},
			wantErrRe: "invalid DeployAptosChainConfig:",
			wantErr:   true,
		},
		{
			name: "error - missing MCMS contract for 2 chains",
			env: deployment.Environment{
				Name:   "test",
				Logger: logger.Test(t),
				AptosChains: map[uint64]deployment.AptosChain{
					743186221051783445:  {},
					4457093679053095497: {},
				},
				ExistingAddresses: getTestAddressBook(
					map[uint64]map[string]deployment.TypeAndVersion{
						4457093679053095497: {
							mockAddress: {Type: "testType"},
						},
						743186221051783445: {
							mockAddress: {Type: "testType"},
						},
					},
				),
			},
			config: DeployAptosChainConfig{
				ContractParamsPerChain: map[uint64]ChainContractParams{
					4457093679053095497: getMockChainContractParams(t, 4457093679053095497),
					743186221051783445:  getMockChainContractParams(t, 743186221051783445),
				},
			},
			wantErrRe: "MCMS contract not deployed for chains:.*(4457093679053095497.*743186221051783445|743186221051783445.*4457093679053095497).*",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := CsDeployAptosChainImp{}
			err := cs.VerifyPreconditions(tt.env, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Regexp(t, tt.wantErrRe, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantState, cs.onChainState)
			}
		})
	}
}
