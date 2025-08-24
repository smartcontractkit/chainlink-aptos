package regulated_token_pool

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"
)

func TestCompile(t *testing.T) {
	t.Parallel()
	output, err := Compile(
		aptos.AccountTwo,
		aptos.AccountThree,
		aptos.AccountFour,
		aptos.AccountTen,
		aptos.AccountFour,
		aptos.AccountFour,
		false,
	)
	require.NoError(t, err)
	require.NotZero(t, output.Metadata, "Compilation resulted in no metadata")
	require.NotZero(t, output.Bytecode, "Compilation resulted in no bytecode")
}
