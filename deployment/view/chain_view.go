package view

import "sync"

type AptosChainView struct {
	ChainSelector uint64 `json:"chainSelector,omitempty"`
	ChainID       string `json:"chainID,omitempty"`

	MCMSWithTimelock MCMSWithTimelockView `json:"mcmsWithTimelock"`

	LinkToken TokenView            `json:"linkToken"`
	Tokens    map[string]TokenView `json:"tokens,omitempty"`

	CCIP    CCIPView               `json:"ccip"`
	Router  map[string]RouterView  `json:"router,omitempty"`
	OnRamp  map[string]OnRampView  `json:"onRamp,omitempty"`
	OffRamp map[string]OffRampView `json:"offRamp,omitempty"`

	TokenPools map[string]map[string]TokenPoolView `json:"poolByTokens,omitempty"`

	UpdateMu *sync.Mutex `json:"-"`
}

func NewAptosChainView() AptosChainView {
	return AptosChainView{
		Tokens:     make(map[string]TokenView),
		Router:     make(map[string]RouterView),
		OnRamp:     make(map[string]OnRampView),
		OffRamp:    make(map[string]OffRampView),
		TokenPools: make(map[string]map[string]TokenPoolView),
		UpdateMu:   &sync.Mutex{},
	}
}
