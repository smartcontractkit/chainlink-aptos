package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/config"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/txm"
)

var DefaultConfigSet = ConfigSet{
	TransactionManager: txm.AptosTxmConfig{
		BroadcastChanSize: 100,
		ConfirmPollSecs:   2,
	},
}

type ConfigSet struct { //nolint:revive
	TransactionManager txm.AptosTxmConfig
}

type WorkflowConfig struct {
	ForwarderAddress string
	// FromAddress      string
	PublicKey string
}

type Chain struct {
	TransactionManager *txm.AptosTxmConfig
	Workflow           WorkflowConfig
}

func (c *Chain) SetDefaults() {
	if c.TransactionManager == nil {
		c.TransactionManager = &DefaultConfigSet.TransactionManager
	}
}

type Node struct {
	Name *string
	URL  *config.URL
}

func (n *Node) ValidateConfig() (err error) {
	if n.Name == nil {
		err = errors.Join(err, config.ErrMissing{Name: "Name", Msg: "required for all nodes"})
	} else if *n.Name == "" {
		err = errors.Join(err, config.ErrEmpty{Name: "Name", Msg: "required for all nodes"})
	}

	if n.URL == nil {
		err = errors.Join(err, config.ErrMissing{Name: "URL", Msg: "required for all nodes"})
	}

	return
}

type TOMLConfigs []*TOMLConfig

func (cs TOMLConfigs) ValidateConfig() (err error) {
	return cs.validateKeys()
}

func (cs TOMLConfigs) validateKeys() (err error) {
	// Unique chain IDs
	chainIDs := config.UniqueStrings{}
	for i, c := range cs {
		if chainIDs.IsDupe(&c.ChainID) {
			err = errors.Join(err, config.NewErrDuplicate(fmt.Sprintf("%d.ChainID", i), c.ChainID))
		}
	}

	// Unique node names
	names := config.UniqueStrings{}
	for i, c := range cs {
		for j, n := range c.Nodes {
			if names.IsDupe(n.Name) {
				err = errors.Join(err, config.NewErrDuplicate(fmt.Sprintf("%d.Nodes.%d.Name", i, j), *n.Name))
			}
		}
	}

	// Unique URLs
	urls := config.UniqueStrings{}
	for i, c := range cs {
		for j, n := range c.Nodes {
			u := (*url.URL)(n.URL)
			if urls.IsDupeFmt(u) {
				err = errors.Join(err, config.NewErrDuplicate(fmt.Sprintf("%d.Nodes.%d.URL", i, j), u.String()))
			}
		}
	}
	return
}

// func (cs *TOMLConfigs) SetFrom(fs *TOMLConfigs) (err error) {
// 	if err1 := fs.validateKeys(); err1 != nil {
// 		return err1
// 	}
// 	for _, f := range *fs {
// 		if f.ChainID == nil {
// 			*cs = append(*cs, f)
// 		} else if i := slices.IndexFunc(*cs, func(c *TOMLConfig) bool {
// 			return c.ChainID != nil && *c.ChainID == *f.ChainID
// 		}); i == -1 {
// 			*cs = append(*cs, f)
// 		} else {
// 			(*cs)[i].SetFrom(f)
// 		}
// 	}
// 	return
// }

type TOMLConfig struct {
	// Do not access directly. Use [IsEnabled]
	Enabled bool
	ChainID string
	Chain
	Nodes Nodes
}

func (c *TOMLConfig) IsEnabled() bool {
	return c.Enabled
}

func (c *TOMLConfig) SetFrom(f *TOMLConfig) {
	c.ChainID = f.ChainID
	c.Enabled = f.Enabled

	setFromChain(&c.Chain, &f.Chain)
	c.Nodes.SetFrom(&f.Nodes)
}

func setFromChain(c, f *Chain) {
	if f.TransactionManager != nil {
		c.TransactionManager = f.TransactionManager
	}

	c.Workflow = f.Workflow
}

func (c *TOMLConfig) ValidateConfig() (err error) {
	if c.ChainID == "" {
		err = errors.Join(err, config.ErrEmpty{Name: "ChainID", Msg: "required for all chains"})
	}

	if len(c.Nodes) == 0 {
		err = errors.Join(err, config.ErrMissing{Name: "Nodes", Msg: "must have at least one node"})
	} else {
		for _, node := range c.Nodes {
			err = errors.Join(err, node.ValidateConfig())
		}
	}

	return
}

func (c *TOMLConfig) TOMLString() (string, error) {
	b, err := toml.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type Nodes []*Node

func (ns *Nodes) SetFrom(fs *Nodes) {
	for _, f := range *fs {
		if f.Name == nil {
			*ns = append(*ns, f)
		} else if i := slices.IndexFunc(*ns, func(n *Node) bool {
			return n.Name != nil && *n.Name == *f.Name
		}); i == -1 {
			*ns = append(*ns, f)
		} else {
			setFromNode((*ns)[i], f)
		}
	}
}

func setFromNode(n, f *Node) {
	if f.Name != nil {
		n.Name = f.Name
	}
	if f.URL != nil {
		n.URL = f.URL
	}
}
