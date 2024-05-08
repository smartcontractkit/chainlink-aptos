//go:build integration

package txm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

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
		accountAddress = hex.EncodeToString(authKey[:])

		logger.Debugw("Created account", "publicKey", hex.EncodeToString([]byte(publicKey)), "accountAddress", accountAddress)
	}

	err := startAptosNode()
	require.NoError(t, err)
	logger.Debugw("Started Aptos node")

	// TODO: use faucet and fund

	keystore := newTestKeystore(t, accountAddress, privateKey)

	config := AptosTxmConfig{
		RPCUrl:            "http://172.254.0.101:8080",
		BroadcastChanSize: 100,
		ConfirmPollSecs:   2,
	}

	runTxmTest(t, logger, config, keystore, accountAddress, publicKey, 10)
}

// Loads an account, assuming no key rotation has taken place.
func loadAccountFromEnv(t *testing.T, logger logger.Logger) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	privateKeyHex := os.Getenv("PRIVATE_KEY")
	if privateKeyHex == "" {
		return nil, nil, ""
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
	accountAddress := hex.EncodeToString(authKey[:])

	logger.Debugw("Loaded account", "publicKey", hex.EncodeToString(publicKeyBytes), "address", accountAddress)

	return privateKey, publicKey, accountAddress
}

func runTxmTest(t *testing.T, logger logger.Logger, config AptosTxmConfig, keystore loop.Keystore, accountAddress string, publicKey ed25519.PublicKey, iterations int) {
	txm := New(logger, keystore, config)
	err := txm.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))
	deployTestContract(t, txm, accountAddress, publicKeyHex)

	for {
		queueLen, unconfirmedLen := txm.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// TODO: error check that the contract was successfully deployed
	logger.Debugw("Deployed test contract")

	expectedValue := 0
	for i := 0; i < iterations; i++ {
		err := txm.Enqueue(
			accountAddress,
			publicKeyHex,
			accountAddress+"::counter::increment",
			[]string{},
			[]string{"address"},
			[]any{accountAddress})
		require.NoError(t, err)
		expectedValue += 1

		err = txm.Enqueue(
			accountAddress,
			publicKeyHex,
			accountAddress+"::counter::increment_mult",
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
}

func deployTestContract(t *testing.T, txm *AptosTxm, fromAddress, publicKeyHex string) {
	packageMetadataHex := "07436f756e7465720100000000000000004034364244394332413846354534313844324535364431373136313942364131314544413036353342454530304636343945453343303843363436354132313038ba011f8b08000000000002ff4d8d4b0ec2300c44f73e05ca9eb46c915820242e5155c86d4c1bb5f9c84e0bc7278182d8799ee7699a88fd8403b5e0d1d1eeb45397b0f844ac6025161b7c61075deb5a012e690c2c99342d4083c6308990b4404f74717efb37955f86d6fddfbb8048de90ef2d893ec714e4ca79f011786a61b0a998634a518e5595e3b874ba0faec2d2dccfd8c976f68149e78202a6b5480eadf794b32c9db15cd0a7e9c24ad5fd3bb2e9bface00581dcba27fa0000000107636f756e746572b4021f8b08000000000002ffc591db4ac4301086effb140382b45a4441bcc8aa37fb1822256dc66e30879a43755dfaeea631dd930bab20ecdc2499cc7c33f38fd4cc0b04fca0b2134848a3bd7268609541306f11ac6384608fcacdb2e8b4cef8c6c13c452ea885575c96c1af0d96c08cee52fa683d151e09f8bbdbe81abe19674f91f87c00385f50d5228bdc9195c047919daf056f2050cd125ebc02aeb8e354f04fcc6913e722706e79abd0145b34a97bac9c9e62caf5609b90ada2d76be750cc8e946f0ccaf0fe51bd84a472451933682d81742980366f9e87eb812e04ba29111ea0d6c6e8f7aa15baa6a292dedda78cc77c8f9efa1c2dfd5cc5610264f77d09379bd0b89fb078c95dbeb799d524c66efaaf0509dd8abfa852028ddb2ea18ee7a955ca295c405dfc8f5643f6059b466d3f8303000000000300000000000000000000000000000000000000000000000000000000000000010e4170746f734672616d65776f726b00000000000000000000000000000000000000000000000000000000000000010b4170746f735374646c696200000000000000000000000000000000000000000000000000000000000000010a4d6f76655374646c696200"
	// this is hacky: we template the bytecode to allow an arbitrary module address.
	moduleBytecodeHex := "a11ceb0b060000000b010004020408030c15042102052318073b54088f014010cf01290af8010a0c8202680dea02020000010100020e0000030600000400010000050201000006030100010806010106030502060c050004060c05030301060c0107080001080101090007636f756e746572056576656e7407436f756e7465720e436f756e7465724368616e67656409696e6372656d656e740e696e6372656d656e745f6d756c740a696e697469616c697a650576616c756504656d6974" + fromAddress + "0000000000000000000000000000000000000000000000000000000000000001126170746f733a3a6d657461646174615f76311500010e436f756e7465724368616e6765640104000000020107030102010703000104010004110b012a000c020a02100014060100000000000000160a020f00150b021000141201380002010104010004130b012a000c040a041000140b020b0318160a040f00150b0410001412013800020201040001050b0006000000000000000012002d0002000000"

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

	err = txm.Enqueue(
		fromAddress,
		publicKeyHex,
		fromAddress+"::counter::initialize",
		[]string{},
		[]string{},
		[]any{})
	require.NoError(t, err)
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
