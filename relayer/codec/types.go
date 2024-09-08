package codec

// / An Aptos module function parameter, which will be mapped to a BCS value.
type AptosFunctionParam struct {
	// The function parameter name.
	Name string
	// The function parameter Move type.
	Type string
	// True if this is a required parameter, false otherwise.
	Required bool
	// If this is not a required parameter and it is not provided, this default value will be used.
	DefaultValue any
}
