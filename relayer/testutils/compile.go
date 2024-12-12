package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
)

type CompilationResult struct {
	PackageMetadata []byte
	BytecodeModules [][]byte
}

func CompileMovePackage(
	t *testing.T,
	contractsDir string,
	namedAddresses map[string]aptos.AccountAddress,
	moduleOrder []string,
) CompilationResult {
	outputDir, err := ioutil.TempDir("", "aptos_compile")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	gitRoot, err := FindGitRoot()
	if err != nil {
		t.Fatalf("Failed to find git root: %v", err)
	}

	packageDir := filepath.Join(gitRoot, "aptos", "contracts", contractsDir)

	if _, err := os.Stat(packageDir); err != nil {
		t.Fatalf("Could not find contract directory: %v", err)
	}

	namedAddressesArg := formatNamedAddresses(namedAddresses)

	args := []string{
		"aptos",
		"move", "compile",
		"--package-dir", packageDir,
		"--named-addresses", namedAddressesArg,
		"--included-artifacts=all",
		"--save-metadata",
		"--output-dir", outputDir,
	}

	cmd := exec.Command(args[0], args[1:]...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to compile contract: %v\nStderr: %s", err, stderr.String())
	}

	if stderr.Len() > 0 {
		t.Logf("Stderr output: %s", stderr.String())
	}

	var result struct {
		Result []string `json:"Result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse compile output: %v", err)
	}

	if len(result.Result) == 0 {
		t.Fatalf("No modules compiled")
	}

	// Read package metadata
	// This is a bug, the package metadata file is still saved in the default output directory (packageDir/build), rather than in the specified output dir.
	// ref: https://github.com/aptos-labs/aptos-core/issues/14285
	packageBuildDir := findBuildDir(t, packageDir)
	metadataFile := filepath.Join(packageBuildDir, "package-metadata.bcs")
	metadata, err := os.ReadFile(metadataFile)
	if err != nil {
		t.Fatalf("Failed to read package metadata file: %v", err)
	}

	buildDir := findBuildDir(t, outputDir)
	bytecodeModules := [][]byte{}
	bytecodeDir := filepath.Join(buildDir, "bytecode_modules")

	// allow providing the module order, because deployment will fail if modules
	// depend on each other and the dependency does not appear first in the list
	// of module bytecode.
	if len(moduleOrder) > 0 {
		for _, moduleName := range moduleOrder {
			expectedPath := filepath.Join(bytecodeDir, moduleName+".mv")
			bytecode, err := os.ReadFile(expectedPath)
			if err != nil {
				t.Fatalf("Failed to read expected bytecode file %s: %v", expectedPath, err)
			}
			bytecodeModules = append(bytecodeModules, bytecode)
		}
	} else {
		files, err := os.ReadDir(bytecodeDir)
		if err != nil {
			t.Fatalf("Failed to read bytecode directory: %v", err)
		}

		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".mv") {
				path := filepath.Join(bytecodeDir, file.Name())
				bytecode, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("Failed to read bytecode file %s: %v", path, err)
				}
				bytecodeModules = append(bytecodeModules, bytecode)
			}
		}
	}

	return CompilationResult{
		PackageMetadata: metadata,
		BytecodeModules: bytecodeModules,
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
