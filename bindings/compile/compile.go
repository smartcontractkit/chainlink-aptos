package compile

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/valyala/fastjson"

	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CompiledPackage struct {
	Metadata []byte
	Bytecode [][]byte
}

// CompilePackage compiles a package with the given name and named addresses.
// It uses the Aptos CLI for compilation, passing the named addresses as arguments.
// The packageName must be one of the packages in the contracts directory that are embedded in the binary.
func CompilePackage(packageName contracts.Package, namedAddresses map[string]aptos.AccountAddress) (CompiledPackage, error) {
	packageDir, ok := contracts.Contracts[packageName]
	if !ok {
		return CompiledPackage{}, fmt.Errorf("package %s not found", packageName)
	}

	// Create a random temporary directory path
	dstDir, err := os.MkdirTemp("", "aptos-*")
	if err != nil {
		return CompiledPackage{}, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			fmt.Printf("failed to remove temporary directory %q: %s", path, err)
		}
	}(dstDir)

	srcDir := filepath.Join(".")
	dstRoot := filepath.Join(dstDir, "contracts")
	packageRoot := filepath.Join(dstRoot, packageDir)

	// Copy the (embedded) source directories into the temporary directory root.
	// We need to copy all contracts (not just the specified package) as different packages might depend on each other.
	err = writeEFS(contracts.Embed, srcDir, dstRoot)
	if err != nil {
		return CompiledPackage{}, fmt.Errorf("failed to copy embedded files to %q: %w", dstRoot, err)
	}

	var namedAddr []string
	for name, addr := range namedAddresses {
		namedAddr = append(namedAddr, fmt.Sprintf("%s=%s", name, addr.String()))
	}

	args := []string{
		"move", "build-publish-payload",
		"--json-output-file", fmt.Sprintf("%s.json", packageName),
		"--assume-yes",
		"--override-size-check",
		"--skip-fetch-latest-git-deps",
	}
	if len(namedAddr) > 0 {
		args = append(args, "--named-addresses", strings.Join(namedAddr, ","))
	}

	cmd := exec.Command("aptos", args...)
	cmd.Dir = packageRoot // Command is run in the temporary destination directory
	// Buffer stdErr and stdOut
	stdOut := &bytes.Buffer{}
	stdErr := &bytes.Buffer{}
	cmd.Stdout = stdOut
	cmd.Stderr = stdErr
	err = cmd.Run()
	if err != nil {
		fmt.Println("aptos command failed:")
		fmt.Println(stdErr.String())
		fmt.Println(stdOut.String())
		return CompiledPackage{}, fmt.Errorf("failed to run aptos command: %w", err)
	}

	// Read output
	outputPath := filepath.Join(packageRoot, fmt.Sprintf("%s.json", packageName))
	outputFile, err := os.Open(outputPath)
	if err != nil {
		return CompiledPackage{}, fmt.Errorf("failed to open output file %q: %w", outputPath, err)
	}
	outputContent, err := io.ReadAll(outputFile)
	if err != nil {
		return CompiledPackage{}, fmt.Errorf("failed to read output file %q: %w", outputPath, err)
	}

	// Parse output
	output := CompiledPackage{}
	v := fastjson.MustParseBytes(outputContent)

	metadata := v.Get("args", "0", "value").GetStringBytes()
	output.Metadata, err = aptos.ParseHex(string(metadata))
	if err != nil {
		return CompiledPackage{}, fmt.Errorf("failed to parse metadata hex %q: %w", string(metadata), err)
	}

	for i, value := range v.GetArray("args", "1", "value") {
		bytecode := value.GetStringBytes()
		bytecodeBytes, err := aptos.ParseHex(string(bytecode))
		if err != nil {
			return CompiledPackage{}, fmt.Errorf("failed to parse bytecode %d hex %q: %w", i, string(bytecode), err)
		}
		output.Bytecode = append(output.Bytecode, bytecodeBytes)
	}

	return output, nil
}

func writeEFS(efs embed.FS, srcDir, dstDir string) error {
	return fs.WalkDir(efs, srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dstDir, path)

		if d.IsDir() {
			err := os.MkdirAll(dstPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to create directory %q: %w", dstPath, err)
			}
			return nil
		}

		srcFile, err := efs.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open src file %q: %w", path, err)
		}
		defer func(srcFile fs.File) {
			_ = srcFile.Close()
		}(srcFile)

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return fmt.Errorf("failed to create dst file %q: %w", dstPath, err)
		}
		defer func(dstFile *os.File) {
			_ = dstFile.Close()
		}(dstFile)

		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			return fmt.Errorf("failed to copy %q to %q: %w", path, dstPath, err)
		}

		return nil
	})
}
