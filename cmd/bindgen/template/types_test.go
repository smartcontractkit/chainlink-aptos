package template

import (
	"testing"
)

func Test_isGenericType(t *testing.T) {
	t.Parallel()
	type args struct {
		s   string
		typ string
	}
	tests := []struct {
		name          string
		args          args
		wantInnerType string
		wantMoveType  string
		wantOk        bool
	}{
		{
			args: args{
				s:   "std::option::Option<u8>",
				typ: "std::option::Option",
			},
			wantInnerType: "u8",
			wantMoveType:  "std::option::Option<u8>",
			wantOk:        true,
		}, {
			args: args{
				s:   "option::Option<u64>",
				typ: "std::option::Option",
			},
			wantInnerType: "u64",
			wantMoveType:  "std::option::Option<u64>",
			wantOk:        true,
		}, {
			args: args{
				s:   "Option<u128>",
				typ: "std::option::Option",
			},
			wantInnerType: "u128",
			wantMoveType:  "std::option::Option<u128>",
			wantOk:        true,
		}, {
			args: args{
				s:   "option::Option<u64>",
				typ: "option::Option",
			},
			wantInnerType: "u64",
			wantMoveType:  "option::Option<u64>",
			wantOk:        true,
		}, {
			args: args{
				s:   "Option<u64>",
				typ: "Option",
			},
			wantInnerType: "u64",
			wantMoveType:  "Option<u64>",
			wantOk:        true,
		}, {
			args: args{
				s:   "std::option::Option<std::option::Option<u8>",
				typ: "std::option::Option",
			},
			wantInnerType: "std::option::Option<u8",
			wantMoveType:  "std::option::Option<std::option::Option<u8>",
			wantOk:        true,
		}, {
			args: args{
				s:   "std::option::Option<u8>",
				typ: "std::option::AnotherOption",
			},
			wantInnerType: "",
			wantMoveType:  "",
			wantOk:        false,
		}, {
			args: args{
				s:   "std::option::Option<u8>",
				typ: "",
			},
			wantInnerType: "",
			wantMoveType:  "",
			wantOk:        false,
		}, {
			args: args{
				s:   "std::option::Option<u8",
				typ: "std::option::Option",
			},
			wantInnerType: "",
			wantMoveType:  "",
			wantOk:        false,
		}, {
			args: args{
				s:   "std::option::Option<u8>",
				typ: "std::option::StdOption",
			},
			wantInnerType: "",
			wantMoveType:  "",
			wantOk:        false,
		}, {
			args: args{
				s:   "vector<u64>",
				typ: "vector",
			},
			wantInnerType: "u64",
			wantMoveType:  "vector<u64>",
			wantOk:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotInnerType, gotMoveType, gotOk := isGenericType(tt.args.s, tt.args.typ)
			if gotInnerType != tt.wantInnerType {
				t.Errorf("isGenericType() gotInnerType = %v, want %v", gotInnerType, tt.wantInnerType)
			}
			if gotMoveType != tt.wantMoveType {
				t.Errorf("isGenericType() gotMoveType = %v, want %v", gotMoveType, tt.wantMoveType)
			}
			if gotOk != tt.wantOk {
				t.Errorf("isGenericType() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}
