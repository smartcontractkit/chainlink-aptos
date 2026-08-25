package main

import "log"

// Aptos transmitter addresses sourced from the CRE capability registry
// (p2pToTransmitterMap values in data-feeds-cre-{prod,staging}/state.json).
// DON: feeds_chain_capabilities[_tnet]_1_zone-{a,b}
var accountsByEnvironment = map[string][]string{
	"staging": {
		// feeds_chain_capabilities_zone-a (aptos-testnet, 4 nodes)
		"0x5686d9cf95413f3570d6bec0e6a6294c43c7a4579c0f158398df87f6c6de93e6",
		"0xf120d4786d2921ed856e937830f0c752ed7bcdfff09fb3049819a3837501ac2a",
		"0x6ac0430dfd584bfa13d6b2090ea17c872e2e8d9c567046881ac61b21ca67e368",
		"0xe6b5385039b210efd7cfb0ee2638b382f0f629941e94a239f3823e5841146238",
	},
	"staging-zone-b": {
		// feeds_chain_capabilities_zone-b (aptos-testnet, 4 nodes)
		"0x292b79f146ccab1b8f0c811a08ae58b850a3532edb3715cea4ef17001f40b32b",
		"0x2aff74345161f20b23b9570f108b35627ec7db30d5496f804464df0efdb5acc8",
		"0x5b2620c7cec16a8dee6f0853867e0dac3e2b09da526d1819f1dd01b0b3f2b696",
		"0x9395bffdd0f731ea3b1d0ab050d9741964fee954a6a84441c4b3c278b6eb9152",
	},
	"prod-testnet": {
		// feeds_chain_capabilities_tnet_1_zone-a (aptos-testnet, 4 nodes)
		"0xee50b205bacf48920c0236c9b92d2a389ffc9a0082f3d65e1dd989bba361a25c",
		"0x5cfee21155f5896515cba93120169422c2157242f3c084d6a1b8bd8e46f2fa1d",
		"0x1841e0d886d2814dacce3eda13e7e283c2ca484247215395a1db4e517c0a7e3e",
		"0x9a06d76f03d26294dd5fe361ba78ca7603b53474b32220211b1dd1645407f74f",
	},
	"prod-testnet-zone-b": {
		// feeds_chain_capabilities_tnet_1_zone-b (aptos-testnet, 4 nodes)
		"0x9a476fb11688c1193116353b5a4677c7878ab6b0930139ba5236338d5e26dcf5",
		"0x0b0e1564a48d7875291cd784cf96b300305caaf3f6fb535a0028716f59a85a4a",
		"0xb0565b9837e51d05aa516948a47e6bc38fdcaafb3fb9d5a267e1fea7c13c9819",
		"0x21e87ce40d4684e3b1bb04c9116d013e952ca8e5cd4111af5b56109748f28552",
	},
	"mainnet": {
		// feeds_chain_capabilities_1_zone-a (aptos-mainnet, 10 nodes)
		"0x09646a5c9af6c278eaaa5e713326fa7c1e42d446a7b951c6f3ce23f65435293f",
		"0x3ece24870cea5e986ba0562e394b83872297c3903eb5ca807c415cb1a8f5a9c5",
		"0x7a5a113b7662d6f221af27185881d1afdc06e1d90bc36bd04342179d43404b5e",
		"0xbe08c52ed419e367259e3d4e26499912ed01631e6731d81edcac4c25e93d5092",
		"0x07c1039dbfbc4eee1aac18373eb0e0db80f4132829bda6d68ad3bee938a577db",
		"0xaeb1b89ca4b05f2a2e0504f2bc002a70071a8895596c0acac25f4db67d8017a9",
		"0xfd86b7aaa9f8dbd53167702741756eeb44c6da00f306c6c39ff76fdf21040dfa",
		"0x5a6bf46fa48a6785af48e67886609e5197e0dfd555bbd8737aed4f5c4af298a2",
		"0xcbccb01c99134756a60acec297c0fa648bb23b1e9016cd7e54313e3383eb2b00",
		"0x6d22150fad3d65812bfc797bfd3ad5322435a6f73991d8ec8a6b498e19e331b5",
	},
	"mainnet-zone-b": {
		// feeds_chain_capabilities_1_zone-b (aptos-mainnet, 10 nodes)
		"0x771825d0cca6eb6c1eedc4ad76f2198ee59c0160c358d37ea2a3c036da85f3e7",
		"0x55d395ec8dc2311d5fa2ac6b878741e3ba6291f249d3f4415e691586f3062220",
		"0xd6484afa7c26aaacbc65a917213259944359ca5fc4e2c49fccd607a4f4d94094",
		"0xb80e004d517d32a433c47e0643fe5d68db2d94c3415b51a062d3b9fd6a22b185",
		"0xa8d846134256999076b56348836fd3995273e2d40b5a535f2554c15242319fb4",
		"0xaa1f64ee54ff4b268e19c4ce6a8c45dc96c51038766a318e864e17cf3ac98f06",
		"0xf7c47ccd3dc6ce0f75007ad309958032a1f67440a69b1d0f61038e8cdb7338be",
		"0xa65e14b1dced61f9d6749aeaa4c4e9eb215fe2be316acdb3543ce60fed9c00bf",
		"0x326f314d4059528508cffca4456a2978f788fe6197fc9e66687d9b599dee4c67",
		"0x6b6da99067b1e5bf15670bf55f7f8789e1c7ad36c53b9279c72776f7127a8f49",
	},
}

func GetAccountsByEnvironment(environment string) []string {
	accounts, ok := accountsByEnvironment[environment]

	if !ok {
		log.Fatalf("Invalid environment: %s. Valid options are: staging, staging-zone-b, prod-testnet, prod-testnet-zone-b, mainnet, mainnet-zone-b", environment)
	}

	return accounts
}

func GetAptosAPIBaseURL(environment string) string {
	environmentURLs := map[string]string{
		"staging":             "https://fullnode.testnet.aptoslabs.com/v1",
		"staging-zone-b":      "https://fullnode.testnet.aptoslabs.com/v1",
		"prod-testnet":        "https://fullnode.testnet.aptoslabs.com/v1",
		"prod-testnet-zone-b": "https://fullnode.testnet.aptoslabs.com/v1",
		"mainnet":             "https://fullnode.mainnet.aptoslabs.com/v1",
		"mainnet-zone-b":      "https://fullnode.mainnet.aptoslabs.com/v1",
	}

	url, exists := environmentURLs[environment]
	if !exists {
		log.Fatalf("Unsupported environment: %s", environment)
	}

	return url
}

func GetAptosNetworkName(environment string) string {
	environmentNetworks := map[string]string{
		"staging":             "testnet",
		"staging-zone-b":      "testnet",
		"prod-testnet":        "testnet",
		"prod-testnet-zone-b": "testnet",
		"mainnet":             "mainnet",
		"mainnet-zone-b":      "mainnet",
	}

	network, exists := environmentNetworks[environment]
	if !exists {
		log.Fatalf("Unsupported environment: %s", environment)
	}

	return network
}
