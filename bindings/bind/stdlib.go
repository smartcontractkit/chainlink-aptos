package bind

import (
	"github.com/aptos-labs/aptos-go-sdk"
)

// StdOption is a binding for 0x1::option::Option
// Vec is guaranteed to be of size <0,1>,
// with 0 representing an unset option::none
// and 1 representing a set option::some
type StdOption[T any] struct {
	Vec []T
}

func (opt StdOption[T]) Value() *T {
	if len(opt.Vec) == 0 {
		return nil
	}
	return &opt.Vec[0]
}

// StdObject is a binding for 0x1::object::Object
type StdObject struct {
	Inner aptos.AccountAddress
}

func (obj StdObject) Address() aptos.AccountAddress {
	return obj.Inner
}

// StdSimpleMap is a binding for 0x1::simple_map::SimpleMap
type StdSimpleMap[K, V any] struct {
	Data []StdElement[K, V]
}

type StdElement[K, V any] struct {
	Key   K
	Value V
}
