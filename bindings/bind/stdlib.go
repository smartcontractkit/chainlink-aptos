package bind

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
