package bindings

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
)

func TestGetFunctionInfo_Global(t *testing.T) {
	type args struct {
		packageModuleFunction []string
	}
	tests := []struct {
		name string
		args args
		want bind.FunctionInfos
	}{
		{
			name: "",
			args: args{
				packageModuleFunction: []string{"mcms", "mcms_account", "transfer_ownership"},
			},
			want: bind.FunctionInfos{
				{
					Package: "mcms",
					Module:  "mcms_account",
					Name:    "transfer_ownership",
					Parameters: []bind.FunctionParameter{
						{
							Name: "to",
							Type: "address",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetFunctionInfo(tt.args.packageModuleFunction...)
			assert.ElementsMatchf(t, got, tt.want, "GetFunctionInfo() = %v, want %v", got.String(), tt.want.String())
		})
	}
}

func TestRegisterWithGlobalRegistry(t *testing.T) {
	// Reset registry
	globalRegistry = make(map[string]map[string]map[string]bind.FunctionInfo)
	type args struct {
		functionInfos []bind.FunctionInfo
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "",
			args: args{
				functionInfos: bind.FunctionInfos{
					{
						Package: "test_package",
						Module:  "test_module",
						Name:    "test_function_name",
						Parameters: []bind.FunctionParameter{
							{
								Name: "parameter1",
								Type: "uint64",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RegisterWithGlobalRegistry(tt.args.functionInfos...)
			fi := GetFunctionInfo("test_package", "test_module", "test_function_name")
			assert.ElementsMatch(t, tt.args.functionInfos, fi)
		})
	}
}
