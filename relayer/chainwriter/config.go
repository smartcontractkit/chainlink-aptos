package chainwriter

type ChainWriterConfig struct {
	Modules map[string]*ChainWriterModule
}

type ChainWriterModule struct {
	// The module name (optional). When not provided, the key in the map under which this module
	// is stored is used.
	Name      string
	Functions map[string]*ChainWriterFunction
}

type ChainWriterFunction struct {
	// The function name (optional). When not provided, the key in the map under which this function
	// is stored is used.
	Name string
	// The public key of the sending account.
	PublicKey string
	// The account address (optional). When not provided, the address is calculated
	// from the public key.
	FromAddress string
	Params      []ChainWriterFunctionParam
}

/// An Aptos module function parameter, which will be mapped to a BCS value.
type ChainWriterFunctionParam struct {
	// The function parameter name.
	Name string
	// The function parameter Move type.
	Type string
	// True if this is a required parameter, false otherwise.
	Required bool
	// If this is not a required parameter and it is not provided, this default value will be used.
	DefaultValue any
}
