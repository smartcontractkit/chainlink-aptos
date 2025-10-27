package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/go-viper/mapstructure/v2"

	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

type CompilationResult struct {
	PackageMetadata []byte
	BytecodeModules [][]byte
}

func CompileMovePackage(
	t *testing.T,
	contractsDir string,
	namedAddresses map[string]aptos.AccountAddress,
) CompilationResult {
	outputDir, err := os.MkdirTemp("", "aptos_compile")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	outputJsonPath := filepath.Join(outputDir, "compiled.json")

	gitRoot, err := FindGitRoot()
	if err != nil {
		t.Fatalf("Failed to find git root: %v", err)
	}

	packageDir := filepath.Join(gitRoot, "contracts", contractsDir)

	if _, err := os.Stat(packageDir); err != nil {
		t.Fatalf("Could not find contract directory: %v", err)
	}

	namedAddressesArg := formatNamedAddresses(namedAddresses)

	args := []string{
		"aptos",
		"move", "build-publish-payload",
		"--override-size-check",
		"--skip-fetch-latest-git-deps",
		"--package-dir", packageDir,
		"--named-addresses", namedAddressesArg,
		"--included-artifacts=sparse",
		"--json-output-file", outputJsonPath,
	}

	cmd := exec.Command(args[0], args[1:]...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to compile contract: %v\nStderr: %s\n\nStdout: %s", err, stderr.String(), stdout.String())
	}

	if stderr.Len() > 0 {
		t.Logf("Stderr output: %s", stderr.String())
	}

	jsonStr, err := os.ReadFile(outputJsonPath)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", outputJsonPath, err)
	}

	var publishPayload struct {
		FunctionId string           `json:"function_id"`
		TypeArgs   []string         `json:"type_args"`
		Args       []map[string]any `json:"args"`
	}

	if err := json.Unmarshal(jsonStr, &publishPayload); err != nil {
		t.Fatalf("Failed to parse publish payload: %v", err)
	}

	if len(publishPayload.Args) != 2 {
		t.Fatalf("Expected 2 args, got %d", len(publishPayload.Args))
	}

	// Parse metadata hex string from Args[0]
	var metadataArg struct {
		Value string `mapstructure:"value"`
	}
	if err := mapstructure.Decode(publishPayload.Args[0], &metadataArg); err != nil {
		t.Fatalf("Failed to decode metadata arg: %v", err)
	}
	metadataHexStr := metadataArg.Value

	// Parse bytecodes hex strings from Args[1]
	var bytecodesArg struct {
		Value []string `mapstructure:"value"`
	}
	if err := mapstructure.Decode(publishPayload.Args[1], &bytecodesArg); err != nil {
		t.Fatalf("Failed to decode bytecodes arg: %v", err)
	}
	bytecodesHexStr := bytecodesArg.Value

	metadata, err := utils.DecodeHexRelaxed(metadataHexStr)
	if err != nil {
		t.Fatalf("Failed to decode metadata hex string: %v", err)
	}

	bytecodes := [][]byte{}
	for _, bytecodeHexStr := range bytecodesHexStr {
		bytecode, err := utils.DecodeHexRelaxed(bytecodeHexStr)
		if err != nil {
			t.Fatalf("Failed to decode bytecode hex string: %v", err)
		}
		bytecodes = append(bytecodes, bytecode)
	}

	return CompilationResult{
		PackageMetadata: metadata,
		BytecodeModules: bytecodes,
	}
}

func formatNamedAddresses(namedAddresses map[string]aptos.AccountAddress) string {
	var pairs []string
	for name, address := range namedAddresses {
		pairs = append(pairs, fmt.Sprintf("%s=%s", name, address.String()))
	}
	return strings.Join(pairs, ",")
}

func findBuildDir(t *testing.T, outputDir string) string {
	t.Helper() // Marks this function as a test helper

	buildDir := filepath.Join(outputDir, "build")
	entries, err := os.ReadDir(buildDir)
	if err != nil {
		t.Fatalf("Failed to read build directory: %v", err)
	}

	var subdirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			if entry.Name() == "locks" {
				continue
			}
			subdirs = append(subdirs, entry.Name())
		}
	}

	switch len(subdirs) {
	case 0:
		t.Fatalf("No subdirectories found in build directory")
	case 1:
		return filepath.Join(buildDir, subdirs[0])
	default:
		t.Fatalf("Multiple subdirectories found in build directory: %v", subdirs)
	}

	return "" // This line will never be reached due to t.Fatalf, but it's needed for compilation
}
