//go:build integration

package txm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/stretchr/testify/require"
)

func TestTxmLocal(t *testing.T) {
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := loadAccountFromEnv(t, logger)
	if privateKey == nil {
		newPublicKey, newPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		privateKey = newPrivateKey
		publicKey = newPublicKey

		authKey := sha3.Sum256(append([]byte(publicKey), 0x00))
		accountAddress = aptos.AccountAddress(authKey)

		logger.Debugw("Created account", "publicKey", hex.EncodeToString([]byte(publicKey)), "accountAddress", accountAddress.String())
	}

	err := startAptosNode()
	require.NoError(t, err)
	logger.Debugw("Started Aptos node")

	rpcUrl := "http://172.254.0.101:8080/v1"
	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	err = fundWithFaucet(logger, client, accountAddress, "http://172.254.0.101:8081")
	require.NoError(t, err)

	//err = waitForAccountFunded(logger, accountAddress, rpcUrl)
	//require.NoError(t, err)

	keystore := newTestKeystore(t, accountAddress.String(), privateKey)

	config := AptosTxmConfig{
		RPCUrl:            rpcUrl,
		BroadcastChanSize: 100,
		ConfirmPollSecs:   2,
	}

	runTxmTest(t, logger, config, keystore, accountAddress, publicKey, 10)
}

// Loads an account, assuming no key rotation has taken place.
func loadAccountFromEnv(t *testing.T, logger logger.Logger) (ed25519.PrivateKey, ed25519.PublicKey, aptos.AccountAddress) {
	privateKeyHex := os.Getenv("PRIVATE_KEY")
	if privateKeyHex == "" {
		return nil, nil, aptos.AccountAddress{}
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	require.NoError(t, err)
	privateKey := ed25519.PrivateKey(privateKeyBytes)

	// TODO: using ed25519.PrivateKey.Public() returns a `crypto.PublicKey` which is a typed `any`, and
	// []byte(publicKey) and publicKey.([]byte) don't seem to work. there's probably a better way to do this?
	// copied from https://cs.opensource.google/go/go/+/refs/tags/go1.22.3:src/crypto/ed25519/ed25519.go;l=57
	publicKeyBytes := make([]byte, ed25519.PublicKeySize)
	copy(publicKeyBytes, []byte(privateKey)[32:])
	publicKey := ed25519.PublicKey(publicKeyBytes)

	authKey := sha3.Sum256(append(publicKeyBytes, 0x00))
	accountAddress := aptos.AccountAddress(authKey)

	logger.Debugw("Loaded account", "publicKey", hex.EncodeToString(publicKeyBytes), "address", accountAddress.String())

	return privateKey, publicKey, accountAddress
}

func fundWithFaucet(logger logger.Logger, client *aptos.NodeClient, address aptos.AccountAddress, faucetUrl string) error {
	faucetClient, err := aptos.NewFaucetClient(client, faucetUrl)
	if err != nil {
		return fmt.Errorf("failed to create faucet client: %+w", err)
	}

	// The faucet takes a while to startup, so add some retries.
	for i := 0; i < 30; i++ {
		err := faucetClient.Fund(address, 100*100000000)
		if err == nil {
			logger.Debugw("Funded using faucet", "address", address.String())
			return nil
		}
		time.Sleep(2 * time.Second)
	}

	return errors.New("failed to fund with faucet")
}

//func waitForAccountFunded(logger logger.Logger, address, rpcUrl string) error {
//for i := 0; i < 30; i++ {
//_, err := client.Account(address)
//if err == nil {
//logger.Debugw("Account ready after funding", "address", address)
//return nil
//}
//time.Sleep(2 * time.Second)
//}

//return errors.New("failed to wait for account to be funded")
//}

func runTxmTest(t *testing.T, logger logger.Logger, config AptosTxmConfig, keystore loop.Keystore, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, iterations int) {
	txm := New(logger, keystore, config)
	err := txm.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))
	deployTestContract(t, txm, accountAddress.String(), publicKeyHex)

	for {
		queueLen, unconfirmedLen := txm.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	logger.Debugw("Deployed test contract")

	// Get the current version so that we can find the transactions quickly after incrementing.
	client, err := txm.GetClient()
	require.NoError(t, err)

	expectedValue := 0
	for i := 0; i < iterations; i++ {
		err := txm.Enqueue(
			accountAddress.String(),
			publicKeyHex,
			accountAddress.String()+"::counter::increment",
			[]string{},
			[]string{"address"},
			[]any{accountAddress})
		require.NoError(t, err)
		expectedValue += 1

		err = txm.Enqueue(
			accountAddress.String(),
			publicKeyHex,
			accountAddress.String()+"::counter::increment_mult",
			[]string{},
			[]string{"address", "u64", "u64"},
			[]any{accountAddress, uint64(3), uint64(4)})
		require.NoError(t, err)
		expectedValue += 3 * 4
	}

	for {
		queueLen, unconfirmedLen := txm.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	resource, err := client.AccountResource(accountAddress, accountAddress.String()+"::counter::Counter")
	require.NoError(t, err)

	data, ok := resource["data"]
	require.True(t, ok)

	dataMap, ok := data.(map[string]any)
	require.True(t, ok)

	value, ok := dataMap["value"]
	require.True(t, ok)

	valueStr, ok := value.(string)
	require.True(t, ok)

	logger.Debugw("Read counter value", "value", valueStr)

	require.Equal(t, fmt.Sprintf("%d", expectedValue), valueStr)
}

func deployTestContract(t *testing.T, txm *AptosTxm, fromAddress, publicKeyHex string) {
	// deploys a Counter test contract:
	//
	// module example::counter {
	//   struct Counter has key, store, drop {
	//       value: u64
	//   }
	//   public entry fun initialize(account: &signer) {
	//       move_to(account, Counter {
	//           value: 0
	//       });
	//   }
	//   public entry fun increment(account: &signer, counter_address: address) acquires Counter {
	//       let counter = borrow_global_mut<Counter>(counter_address);
	//       counter.value = counter.value + 1;
	//   }
	//   public entry fun increment_mult(account: &signer, counter_address: address, a: u64, b: u64) acquires Counter {
	//       let counter = borrow_global_mut<Counter>(counter_address);
	//       counter.value = counter.value + (a * b);
	//   }
	// }

	packageMetadataHex := "07436f756e7465720100000000000000004031333133423630374646374432383638464442413031354530303344363733383935464134343944354346434434414239314137344330424332453830324541691f8b08000000000002ff4dcb4d0a80201040e1fd9c42dc277680561d4324861c2aca1f1c958e9fb56afb3e9e49b89eb89185809ec424e41c6b28942534ca7cc4f0b65169a525602d7bccdc8bb100069dcbc44c6c816ef4e9fafe457672d4861f3fdc6349df660000000107636f756e746572fe011f8b08000000000002ffc551c94ec4300cbdf72bde09b51021901087b25cf8902a49cd1091a564191850ff9d4c9429c32201a7f1c5f6f3f2fc64e3c6a409f4c2cda4a9efa54b3692c75b836c21fa2423ee2af8c0031e69c332ee3c318cde4db5736b6bae13f5489717059a9be2a624b492201bfd06f7c942591515d7ea955a2e0b5f8fa3a056967cb7b7cdb8350dd1ed7ad872c547cb1ee9d902ceddd52ff4d293c9f9377686aa7ee0e3e829841e35e8c0e5535239fce10a4d7137881b08e7bd7b1e56da09ae0793e2759db86dbf6caf776ead564e8b98bce4737e82f33f4aca7cfa3fba1878f9178328fed03a5b8e6388e58173f30e8a698a259f02000000000000"

	// this is hacky: we template the bytecode to allow an arbitrary module address.
	fromAddressStripped := fromAddress
	if strings.HasPrefix(fromAddressStripped, "0x") {
		fromAddressStripped = fromAddressStripped[2:]
	}
	moduleBytecodeHex := "a11ceb0b060000000901000202020403060f05151207273a0861200a8101050c8601560ddc0102000000010e0000020001000003020100000403010002060c050004060c05030301060c0107080007636f756e74657207436f756e74657209696e6372656d656e740e696e6372656d656e745f6d756c740a696e697469616c697a650576616c7565" + fromAddressStripped + "00020105030001040100040c0b012a000c020a02100014060100000000000000160b020f0015020101040100040e0b012a000c040a041000140b020b0318160b040f0015020201040001050b0006000000000000000012002d0002000000"

	packageMetadataBytes, err := hex.DecodeString(packageMetadataHex)
	require.NoError(t, err)

	moduleBytecodeBytes, err := hex.DecodeString(moduleBytecodeHex)
	require.NoError(t, err)

	err = txm.Enqueue(
		fromAddress,
		publicKeyHex,
		"0x1::code::publish_package_txn",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{packageMetadataBytes, [][]byte{moduleBytecodeBytes}},
	)
	require.NoError(t, err)

	// TODO: check account module to make sure it was published.

	err = txm.Enqueue(
		fromAddress,
		publicKeyHex,
		fromAddress+"::counter::initialize",
		[]string{},
		[]string{},
		[]any{})
	require.NoError(t, err)

	// TODO: check account resource to make sure it was initialized.
}

type testKeystore struct {
	t          *testing.T
	address    string
	privateKey ed25519.PrivateKey
}

var _ loop.Keystore = &testKeystore{}

func newTestKeystore(t *testing.T, address string, privateKey ed25519.PrivateKey) *testKeystore {
	return &testKeystore{t: t, address: address, privateKey: privateKey}
}

func (tk *testKeystore) Sign(ctx context.Context, id string, hash []byte) ([]byte, error) {
	require.Equal(tk.t, tk.address, id)

	// used to check if the account exists.
	if hash == nil {
		return nil, nil
	}

	return ed25519.Sign(tk.privateKey, hash), nil
}

func (tk *testKeystore) Accounts(ctx context.Context) ([]string, error) {
	return []string{tk.address}, nil
}

// Finds the closest git repo root, assuming that a directory with a .git directory is a git repo.
func findGitRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		gitDir := filepath.Join(currentDir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return currentDir, nil
		}

		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			return "", fmt.Errorf("no Git repository found")
		}

		currentDir = parentDir
	}
}

func startAptosNode() error {
	gitRoot, err := findGitRoot()
	if err != nil {
		return fmt.Errorf("failed to find Git root: %v", err)
	}

	scriptPath := filepath.Join(gitRoot, "aptos/scripts/devnet.sh")
	cmd := exec.Command(scriptPath)

	output, err := cmd.CombinedOutput()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Failed to start devnet, dumping output:\n%s\n", string(output))
			return fmt.Errorf("Failed to start devnet, bad exit code: %v", exitError.ExitCode())
		}
		return fmt.Errorf("Failed to start devnet: %+v", err)
	}

	return nil
}
