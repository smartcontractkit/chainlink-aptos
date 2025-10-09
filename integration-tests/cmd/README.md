# Test Helper CLI

This package contains a CLI that can be used to manually perform test-related operations

To run it, from the `integration-tests` folder, run:
```
go run ./cmd ...
```

To view all available commands and their flags run 
```
go run ./cmd --help
```

## CCIP

Contains sub-commands related to CCIP operations. For more information run:
```
go run ./cmd ccip --help
```

### Deploy

Will deploy a new CCIP environment to a given network. For more information, run:
```
go run ./cmd ccip deploy --help
```

Flags:
```
      --faucetUrl string    The Faucet URL to use (default "http://localhost:8081/")
      --fundAmount uint     The amount of APT to fund the account with. If specified, will use the provided faucet to fund the deployer account
  -k, --privateKey string   The Aptos private key to use for the deployment. If not specified, a random key will be generated and funded with 100 APT using the faucet
  -r, --rpcUrl string       The Aptos RPC URL to use (default "http://localhost:8080/v1")
```

After a successful deployment, all the resulting addresses will be printed:
```
2025-10-09T19:34:25.850+0200    INFO    ccip/cmd.go:88  CCIP deployment successful:
2025-10-09T19:34:25.850+0200    INFO    ccip/cmd.go:89  CCIP: 0xb3ed5bbae8d295cc9962f37243f40a3803174fc3c23de313f1856f3b802e2e4f
2025-10-09T19:34:25.850+0200    INFO    ccip/cmd.go:90  MCMS: 0x9e9ab15ae3520f49f70bbfc71a8c0f5d26bc81fffa0ac94aa3990bfd02d60aac
2025-10-09T19:34:25.850+0200    INFO    ccip/cmd.go:91  LINK: 0xa2b345745f26c0ff04617af143bafd63d21dc45a153b870a7dc4f40e9ba3b6d5
2025-10-09T19:34:25.850+0200    INFO    ccip/cmd.go:92  Token Pool: 0xeae88ee064497767a4a914deac28912e99b4b419b17a1be40707756cffb18020
```