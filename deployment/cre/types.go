// Package cre contains changesets that govern the Aptos CRE forwarders (platform = zone-a,
// platform_secondary = zone-b) through a dedicated MCMS and the forwarder_mcms_adapter package.
//
// Lifecycle:
//  1. DeployCREMCMS: deploy and configure an MCMS; its proposal makes MCMS own itself.
//  2. DeployForwarderAdapter: publish the adapter through that MCMS (proposal).
//  3. TransferForwarderOwnership: current owner proposes the adapter's MCMS owner account.
//     Direct mode for deployer-owned forwarders; native-multisig owners use their own tooling.
//  4. AcceptForwarderOwnership: MCMS accepts through the adapter (proposal).
//  5. SetForwarderConfig / ClearForwarderConfig: direct while the deployer owns a forwarder,
//     MCMS proposal once the adapter's owner account does.
//
// Forwarders are resolved from the datastore by zone (type AptosForwarder, qualifier = zone).
package cre

import (
	"errors"
	"fmt"
	"slices"

	"github.com/Masterminds/semver/v3"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"

	"github.com/smartcontractkit/chainlink-aptos/contracts"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
)

const (
	// AptosForwarderType is the datastore type of an existing CRE forwarder package, qualified by zone.
	AptosForwarderType cldf.ContractType = "AptosForwarder"
	// AptosForwarderMcmsAdapterType is the adapter package (its code object address).
	AptosForwarderMcmsAdapterType cldf.ContractType = "AptosForwarderMcmsAdapter"
	// AptosForwarderMcmsAdapterOwnerType is the adapter's MCMS owner account: the address MCMS
	// signs as through the adapter, i.e. the owner both forwarders must be handed to.
	AptosForwarderMcmsAdapterOwnerType cldf.ContractType = "AptosForwarderMcmsAdapterOwner"

	// DefaultQualifier selects the CRE MCMS and adapter instance when none is given.
	DefaultQualifier = "CLLCRE"
	// forwarderModule is the module both forwarder packages expose.
	forwarderModule = "forwarder"
	// maxOracles mirrors forwarder::MAX_ORACLES.
	maxOracles = 31
)

var (
	// Version1_0_0 is the datastore version of every ref this package reads or writes.
	Version1_0_0 = *semver.MustParse("1.0.0")
	// AptosMCMSType is the shared Aptos MCMS type; the CRE instance is told apart by qualifier.
	// Datastores are domain-scoped, so it cannot be confused with CCIP's (qualifier CLLCCIP).
	AptosMCMSType = shared.AptosMCMSType
)

// Zone names a forwarder: zone-a is the primary (ChainlinkPlatform), zone-b the secondary
// (ChainlinkPlatformSecondary). It is the forwarder's datastore qualifier.
type Zone string

const (
	ZoneA Zone = "zone-a"
	ZoneB Zone = "zone-b"
)

// AllZones lists the zones in adapter order (primary, secondary).
var AllZones = []Zone{ZoneA, ZoneB}

func (z Zone) Validate() error {
	if z != ZoneA && z != ZoneB {
		return fmt.Errorf("invalid zone %q: must be %q or %q", z, ZoneA, ZoneB)
	}
	return nil
}

// PackageName is the forwarder package name deployed for this zone.
func (z Zone) PackageName() string {
	if z == ZoneB {
		return string(contracts.PlatformSecondary)
	}
	return string(contracts.Platform)
}

// onChainPackageName is the Move package name (from Move.toml) of the zone's forwarder, as
// recorded in 0x1::code::PackageRegistry.
func (z Zone) onChainPackageName() string {
	if z == ZoneB {
		return "ChainlinkPlatformSecondary"
	}
	return "ChainlinkPlatform"
}

// zonesOrAll defaults an empty zone list to both zones and rejects invalid or repeated zones.
func zonesOrAll(zones []Zone) ([]Zone, error) {
	if len(zones) == 0 {
		return AllZones, nil
	}
	var errs []error
	for i, z := range zones {
		if err := z.Validate(); err != nil {
			errs = append(errs, err)
		}
		if slices.Contains(zones[:i], z) {
			errs = append(errs, fmt.Errorf("zone %q listed twice", z))
		}
	}
	return zones, errors.Join(errs...)
}

func qualifierOrDefault(q string) string {
	if q == "" {
		return DefaultQualifier
	}
	return q
}

// DON identifies the DON whose report signers a forwarder accepts.
type DON struct {
	// ID is the DON ID (forwarder don_id).
	ID uint32 `json:"id" yaml:"id"`
	// ConfigVersion is the forwarder config_version for this DON config.
	ConfigVersion uint32 `json:"configVersion" yaml:"configVersion"`
	// F is the fault tolerance; the forwarder requires at least 3F+1 signers.
	F uint8 `json:"f" yaml:"f"`
	// NodeIDs identify the DON's nodes in the job distributor: CSA public keys, "p2p_…" peer
	// IDs or "node_…" JD node IDs (all entries must use the same form). Each node's Aptos OCR2
	// onchain signing key becomes a forwarder oracle.
	NodeIDs []string `json:"nodeIDs" yaml:"nodeIDs"`
}

func (d DON) Validate() error {
	if d.F == 0 {
		return errors.New("DON F must be greater than 0")
	}
	if len(d.NodeIDs) == 0 {
		return errors.New("DON node IDs are required")
	}
	return nil
}

// validateSignerCount applies the forwarder's set_config bounds to the resolved signers.
func validateSignerCount(f uint8, n int) error {
	if n < 3*int(f)+1 {
		return fmt.Errorf("forwarder needs at least 3F+1 = %d signers for F = %d, the DON resolved to %d", 3*int(f)+1, f, n)
	}
	if n > maxOracles {
		return fmt.Errorf("DON resolved to %d signers, the forwarder accepts at most %d", n, maxOracles)
	}
	return nil
}

// DeployCREMCMSConfig configures DeployCREMCMS.
type DeployCREMCMSConfig struct {
	ChainSelector uint64 `json:"chainSelector" yaml:"chainSelector"`
	// Qualifier of the MCMS datastore ref. Defaults to DefaultQualifier.
	Qualifier string `json:"qualifier,omitempty" yaml:"qualifier,omitempty"`
	// MCMS is the signer configuration for each role plus the timelock min delay.
	MCMS cldfproposalutils.MCMSWithTimelockConfig `json:"mcms" yaml:"mcms"`
	// TimelockConfig shapes the follow-up proposal (MCMS accepts ownership of itself and sets
	// the min delay). That proposal must execute before the adapter can be published.
	TimelockConfig cldfproposalutils.TimelockConfig `json:"timelockConfig" yaml:"timelockConfig"`
}

// DeployForwarderAdapterConfig configures DeployForwarderAdapter.
type DeployForwarderAdapterConfig struct {
	ChainSelector uint64 `json:"chainSelector" yaml:"chainSelector"`
	// Qualifier selects the MCMS and is the qualifier of the adapter refs written. Defaults to
	// DefaultQualifier.
	Qualifier string `json:"qualifier,omitempty" yaml:"qualifier,omitempty"`
	// Seed for mcms_deployer's code object. Each seed can be used once; defaults to a
	// timestamped seed.
	Seed           string                           `json:"seed,omitempty" yaml:"seed,omitempty"`
	TimelockConfig cldfproposalutils.TimelockConfig `json:"timelockConfig" yaml:"timelockConfig"`
}

// TransferForwarderOwnershipConfig configures TransferForwarderOwnership.
type TransferForwarderOwnershipConfig struct {
	ChainSelector uint64 `json:"chainSelector" yaml:"chainSelector"`
	// Qualifier selects the MCMS and adapter. Defaults to DefaultQualifier.
	Qualifier string `json:"qualifier,omitempty" yaml:"qualifier,omitempty"`
	// Zones to transfer. Defaults to both.
	Zones []Zone `json:"zones,omitempty" yaml:"zones,omitempty"`
	// To is the proposed new owner. Defaults to the adapter's MCMS owner account in direct
	// mode; required in MCMS mode (handing a forwarder back out of MCMS).
	To string `json:"to,omitempty" yaml:"to,omitempty"`
	// MCMS, when set, builds a proposal through the adapter (the forwarder must be owned by
	// the adapter's MCMS owner account). When nil the deployer key sends directly (the
	// forwarder must be owned by the deployer).
	MCMS *cldfproposalutils.TimelockConfig `json:"mcms,omitempty" yaml:"mcms,omitempty"`
}

// AcceptForwarderOwnershipConfig configures AcceptForwarderOwnership.
type AcceptForwarderOwnershipConfig struct {
	ChainSelector uint64 `json:"chainSelector" yaml:"chainSelector"`
	Qualifier     string `json:"qualifier,omitempty" yaml:"qualifier,omitempty"`
	// Zones to accept. Defaults to both.
	Zones []Zone `json:"zones,omitempty" yaml:"zones,omitempty"`
	// MCMS, when set, accepts as the adapter's MCMS owner account via a proposal. When nil the
	// deployer accepts directly.
	MCMS *cldfproposalutils.TimelockConfig `json:"mcms,omitempty" yaml:"mcms,omitempty"`
}

// SetForwarderConfigConfig configures SetForwarderConfig.
type SetForwarderConfigConfig struct {
	ChainSelector uint64 `json:"chainSelector" yaml:"chainSelector"`
	Qualifier     string `json:"qualifier,omitempty" yaml:"qualifier,omitempty"`
	Zone          Zone   `json:"zone" yaml:"zone"`
	DON           DON    `json:"don" yaml:"don"`
	// MCMS selects proposal mode; nil sends directly with the deployer key.
	MCMS *cldfproposalutils.TimelockConfig `json:"mcms,omitempty" yaml:"mcms,omitempty"`
}

// ClearForwarderConfigConfig configures ClearForwarderConfig.
type ClearForwarderConfigConfig struct {
	ChainSelector uint64                            `json:"chainSelector" yaml:"chainSelector"`
	Qualifier     string                            `json:"qualifier,omitempty" yaml:"qualifier,omitempty"`
	Zone          Zone                              `json:"zone" yaml:"zone"`
	DONID         uint32                            `json:"donID" yaml:"donID"`
	ConfigVersion uint32                            `json:"configVersion" yaml:"configVersion"`
	MCMS          *cldfproposalutils.TimelockConfig `json:"mcms,omitempty" yaml:"mcms,omitempty"`
}
