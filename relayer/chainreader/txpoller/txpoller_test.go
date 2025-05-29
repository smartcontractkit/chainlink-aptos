package txpoller

import (
	"encoding/json"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"
)

func TestFetchOneTransaction(t *testing.T) {
	rpcURL := "https://fullnode.testnet.aptoslabs.com/v1"
	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)

	accAddress := &aptos.AccountAddress{}
	err = accAddress.ParseStringRelaxed("0xc084ae8dd56ce0e949324ea9ee5f01be64b1bf70e48a4f239c82ee40d7f03421")
	require.NoError(t, err)

	offset := uint64(2323)
	limit := uint64(1)

	txns, err := client.AccountTransactions(*accAddress, &offset, &limit)
	require.NoError(t, err)

	if len(txns) == 0 {
		t.Log("No transactions found")
		return
	}

	txn := txns[0]
	userTxn, err := txn.UserTransaction()
	require.NoError(t, err)

	data, err := json.MarshalIndent(userTxn, "", "  ")
	require.NoError(t, err)

	t.Logf("Fetched User Transaction:\n%s", data)
}
