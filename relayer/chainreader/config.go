package chainreader

type ChainReaderConfig struct {
	Modules map[string]*ChainReaderModule
}

type ChainReaderModule struct {
	// The module name (optional). When not provided, the key in the map under which this module
	// is stored is used.
	Name      string
	Functions map[string]*ChainReaderFunction
}

type ChainReaderFunction struct {
	// The function name (optional). When not provided, the key in the map under which this function
	// is stored is used.
	Name   string
	Params []ChainReaderFunctionParam
}

// / An Aptos module function parameter, which will be mapped to a BCS value.
type ChainReaderFunctionParam struct {
	// The function parameter name.
	Name string
	// The function parameter Move type.
	Type string
	// True if this is a required parameter, false otherwise.
	Required bool
	// If this is not a required parameter and it is not provided, this default value will be used.
	DefaultValue any
}
