# Contract Registry Generator

Automatically generates a Go registry of contract function information from Aptos move bindings.

## Overview

This tool scans Go binding files for `const FunctionInfo` declarations and generates a comprehensive registry mapping:
```
package → module → function name → FunctionInfo struct
```

The generated registry enables runtime function lookup and is particularly useful for:
- Decoding proposals
- Function discovery and validation

## How It Works

1. **Scans** all `.go` files in the bindings directory
2. **Extracts** `const FunctionInfo = \`...\`` declarations using regex
3. **Parses** the JSON function metadata 
4. **Generates** `contracts_registry.go` with a structured map and helper functions

## Usage

```bash
go run ./cmd/registergen/main.go --input=bindings --output=bindings/bind
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--input` | Path to directory containing Go binding files | `bindings` |
| `--output` | Output directory (file will be named `contracts_registry.go`) | `.` |
