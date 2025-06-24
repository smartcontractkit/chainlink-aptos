package main

import (
	_ "embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
)

//go:embed go.tmpl
var templateContent string

func main() {
	bindingsPath := flag.String("input", "bindings", "path to the bindings directory")
	outputPath := flag.String("output", ".", "output directory path")
	flag.Parse()

	functionInfoMap, err := parseFunctionInfoFromPath(*bindingsPath)
	if err != nil {
		log.Fatal(err)
	}

	// Create the full output file path
	outputFile := filepath.Join(*outputPath, "contracts_registry.go")

	// Generate the registry file
	err = generateRegistry(functionInfoMap, outputFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated registry file: %s\n", outputFile)
}

// generateRegistry creates the registry.go file using the embedded template
func generateRegistry(functionInfoMap map[string]map[string]map[string]bind.FunctionInfo, outputPath string) error {
	tmpl, err := template.New("registry").Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, functionInfoMap)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// parseFunctionInfoFromPath scans the given directory for Go files containing
// "const FunctionInfo =" and parses them into a nested map structure
func parseFunctionInfoFromPath(rootPath string) (map[string]map[string]map[string]bind.FunctionInfo, error) {
	result := make(map[string]map[string]map[string]bind.FunctionInfo)

	// Regex pattern to match: const FunctionInfo = `...`
	pattern := regexp.MustCompile(`const\s+FunctionInfo\s*=\s*` + "`" + `([^` + "`" + `]+)` + "`")

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Only process .go files
		if !strings.HasSuffix(path, ".go") || d.IsDir() {
			return nil
		}

		// Read the file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		// Find FunctionInfo constant
		matches := pattern.FindStringSubmatch(string(content))
		if len(matches) < 2 {
			// No FunctionInfo found in this file
			return nil
		}

		// Extract the JSON string (group 1 from regex)
		jsonStr := matches[1]

		// Parse the JSON into FunctionInfo structs
		functionInfos, err := bind.ParseFunctionInfo(jsonStr)
		if err != nil {
			return fmt.Errorf("failed to parse FunctionInfo in %s: %w", path, err)
		}

		// Add to the result map
		for _, funcInfo := range functionInfos {
			// Initialize nested maps if they don't exist
			if result[funcInfo.Package] == nil {
				result[funcInfo.Package] = make(map[string]map[string]bind.FunctionInfo)
			}
			if result[funcInfo.Package][funcInfo.Module] == nil {
				result[funcInfo.Package][funcInfo.Module] = make(map[string]bind.FunctionInfo)
			}

			// Add the function info
			result[funcInfo.Package][funcInfo.Module][funcInfo.Name] = funcInfo
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", rootPath, err)
	}

	return result, nil
}
