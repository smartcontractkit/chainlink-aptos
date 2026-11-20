package cre

import (
	"errors"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-aptos/bindings/platform"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform_secondary"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
)

var _ cldf.ChangeSetV2[DeployForwardersConfig] = DeployForwarders{}

// DeployForwardersConfig configures DeployForwarders.
type DeployForwardersConfig struct {
	ChainSelector uint64 `json:"chainSelector" yaml:"chainSelector"`
	// Zones to deploy: zone-a deploys ChainlinkPlatform, zone-b ChainlinkPlatformSecondary.
	// Defaults to both.
	Zones []Zone `json:"zones,omitempty" yaml:"zones,omitempty"`
	// Owner is the forwarders' initial owner. Defaults to the deployer, which can then configure
	// them directly and hand them to MCMS with TransferForwarderOwnership.
	Owner string `json:"owner,omitempty" yaml:"owner,omitempty"`
}

// DeployForwarders deploys the CRE forwarder packages with the deployer key, each to a new
// object, and records them as AptosForwarder refs qualified by zone: the refs every other
// changeset in this package resolves forwarders by.
type DeployForwarders struct{}

func (DeployForwarders) VerifyPreconditions(env cldf.Environment, cfg DeployForwardersConfig) error {
	_, err := planDeployForwarders(env, cfg)
	return err
}

type deployForwardersPlan struct {
	zones []Zone
	owner aptos.AccountAddress
}

func planDeployForwarders(env cldf.Environment, cfg DeployForwardersConfig) (deployForwardersPlan, error) {
	chain, err := aptosChain(env, cfg.ChainSelector)
	if err != nil {
		return deployForwardersPlan{}, err
	}
	zones, err := zonesOrAll(cfg.Zones)
	if err != nil {
		return deployForwardersPlan{}, err
	}
	plan := deployForwardersPlan{zones: zones}
	if cfg.Owner != "" {
		if err := plan.owner.ParseStringRelaxed(cfg.Owner); err != nil {
			return deployForwardersPlan{}, fmt.Errorf("invalid owner %q: %w", cfg.Owner, err)
		}
	} else if plan.owner, err = deployerAddress(chain); err != nil {
		return deployForwardersPlan{}, err
	}

	planned := make([]shared.PlannedRef, 0, len(zones))
	for _, zone := range zones {
		planned = append(planned, shared.PlannedRef{
			ChainSelector: cfg.ChainSelector,
			Type:          AptosForwarderType,
			Version:       Version1_0_0,
			Qualifier:     string(zone),
			MultiInstance: true,
		})
	}
	return plan, errors.Join(shared.ValidatePlannedRefs(env, false, planned))
}

func (DeployForwarders) Apply(env cldf.Environment, cfg DeployForwardersConfig) (cldf.ChangesetOutput, error) {
	plan, err := planDeployForwarders(env, cfg)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	chain, err := aptosChain(env, cfg.ChainSelector)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	ds := datastore.NewMemoryDataStore()
	for _, zone := range plan.zones {
		var (
			addr aptos.AccountAddress
			tx   *api.PendingTransaction
		)
		if zone == ZoneB {
			addr, tx, _, err = platform_secondary.DeployToObject(chain.DeployerSigner, chain.Client, plan.owner)
		} else {
			addr, tx, _, err = platform.DeployToObject(chain.DeployerSigner, chain.Client, plan.owner)
		}
		if err := confirm(chain, tx, err, fmt.Sprintf("deploy %s forwarder (%s)", zone, zone.onChainPackageName())); err != nil {
			return cldf.ChangesetOutput{}, err
		}

		tv := cldf.NewTypeAndVersion(AptosForwarderType, Version1_0_0)
		tv.AddLabel(zone.onChainPackageName())
		if err := shared.RecordAddress(nil, ds, cfg.ChainSelector, addr.StringLong(), tv, string(zone)); err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("record %s forwarder %s: %w", zone, addr.StringLong(), err)
		}
		env.Logger.Infow("Deployed CRE forwarder", "zone", zone, "package", zone.onChainPackageName(),
			"forwarder", addr.StringLong(), "owner", plan.owner.StringLong(), "tx", tx.Hash)
	}
	return cldf.ChangesetOutput{DataStore: ds}, nil
}
