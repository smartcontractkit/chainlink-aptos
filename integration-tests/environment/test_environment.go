package env

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	chainselectors "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cldfchain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/environment"

	"github.com/smartcontractkit/chainlink-aptos/deployment/pkg/ops"
)

type EnvironmentType int

const (
	CTF EnvironmentType = iota
)

type ChainsEnvironmentConfig struct {
	EVMChains   int
	AptosChains int
}

type TestEnvironmentBuilder struct {
	Logger                  logger.Logger
	Type                    EnvironmentType
	ChainsEnvironmentConfig ChainsEnvironmentConfig
}

func NewTestEnvironmentBuilder(lggr logger.Logger) *TestEnvironmentBuilder {
	return &TestEnvironmentBuilder{
		Logger: lggr,
		Type:   CTF,
	}
}

func (b *TestEnvironmentBuilder) CTF() *TestEnvironmentBuilder {
	b.Type = CTF
	return b
}

func (b *TestEnvironmentBuilder) WithAptos() *TestEnvironmentBuilder {
	b.ChainsEnvironmentConfig.AptosChains = 1
	return b
}

func (b *TestEnvironmentBuilder) WithEVM() *TestEnvironmentBuilder {
	b.ChainsEnvironmentConfig.EVMChains = 1
	return b
}

func (b *TestEnvironmentBuilder) WithEVMN(n int) *TestEnvironmentBuilder {
	b.ChainsEnvironmentConfig.EVMChains = n
	return b
}

func (b *TestEnvironmentBuilder) Build(t *testing.T) (cldf.Environment, error) {
	switch b.Type {
	case CTF:
		return b.newCTFBasedEnvironment(t)
	default:
		return cldf.Environment{}, fmt.Errorf("unsupported environment type: %d", b.Type)
	}
}

func (b *TestEnvironmentBuilder) newCTFBasedEnvironment(t *testing.T) (cldf.Environment, error) {
	loadOpts := []environment.LoadOpt{
		environment.WithLogger(b.Logger),
	}

	if b.ChainsEnvironmentConfig.EVMChains > 0 {
		loadOpts = append(loadOpts, environment.WithEVMSimulatedN(t, b.ChainsEnvironmentConfig.EVMChains))
	}
	if b.ChainsEnvironmentConfig.AptosChains > 0 {
		loadOpts = append(loadOpts, environment.WithAptosContainerN(t, b.ChainsEnvironmentConfig.AptosChains))
	}

	env, err := environment.New(t.Context(), loadOpts...)
	if err != nil {
		return cldf.Environment{}, fmt.Errorf("failed to create environment: %w", err)
	}

	env.OperationsBundle.OperationRegistry = ops.Registry

	return *env, nil
}

// BuildWithExtraEVMChains returns an environment with the given number of simulated EVM chains.
func BuildAptosEVMTestEnv(t *testing.T, lggr logger.Logger, evmChains int) cldf.Environment {
	env, err := NewTestEnvironmentBuilder(lggr).
		CTF().
		WithAptos().
		WithEVMN(evmChains).
		Build(t)
	require.NoError(t, err)
	return env
}

// AptosSelector returns the first Aptos chain selector in the environment.
func AptosSelector(env cldf.Environment) uint64 {
	selectors := env.BlockChains.ListChainSelectors(cldfchain.WithFamily(chainselectors.FamilyAptos))
	if len(selectors) == 0 {
		panic("no aptos chains in environment")
	}
	return selectors[0]
}

// EVMSelectors returns all EVM chain selectors in the environment.
func EVMSelectors(env cldf.Environment) []uint64 {
	return env.BlockChains.ListChainSelectors(cldfchain.WithFamily(chainselectors.FamilyEVM))
}

