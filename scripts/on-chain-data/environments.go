package main

import "log"

var accountsByEnvironment = map[string][]string{
	"staging": {
		"0x426612d24bf1a44f20b0f957c96b940b9da20f72aaffaeddc47c0827c5725ac2", // node 0 (NodeID = '1') - RPC aptos_primary_quiknode
		"0x3e29e2591e63b088c496f9d20d5ac71e049452c4f445b376de0ab9f90cfec0d6", // node 1 (NodeID = '2') - RPC aptos_primary_p2pify
		"0xa9945161773dc6149748e2ce7baa65a5f4feacc34fa725b21f1762f4d3f0ed25", // node 2 (NodeID = '3') - RPC aptos_primary_linkpool
		"0x60d4a83b62a6bfa828c6c555ea40b4a67a4b683f0ec559c3d85d796166455e3a", // node 3 (NodeID = '4') - RPC aptos_primary_linkpool
	},
	"staging-zone-b": {
		"0x9a14574f1f99b1becb348cdef53deaef66f148d055f2e41c7021db9670453f20", // node 0 (NodeID = '1')
		"0x4397633e4fba12054d6270f59094752642ab8445aa4c89e1f340759884cffa33", // node 1 (NodeID = '2')
		"0x74b14f822a761e1e0d0436ac0a87cb7a984a260c9b6999a8a4282b9cf95ce3ba", // node 2 (NodeID = '3')
		"0xe0f6be3bbf30eb6498957abf33f66ef50adb61bda4201b37d6ec53d0efb79146", // node 3 (NodeID = '4')
	},
	"prod-testnet": {
		"0x9a28fa835ea14231158c9b0aa7e874076c4b932b8d7f5d936410990a8735e065", // node 0 - RPC aptos_primary_p2pify
		"0xd888353aea5c713ec3489bbd5eb81e09462c2ea24c5fddb75082c3f211eb7852", // node 1 - RPC aptos_primary_linkpool
		"0x4f053f65e333c94997b068561d17a76ed71dce377e436fd088473c577b848aa6", // node 2 - RPC aptos_primary_quiknode
		"0x4049c59004c446370aecff9f6c799198e18b735b398b81b45102f28afbdda18b", // node 3 - RPC aptos_primary_p2pify
		"0x63d8d44b8568f97d97afc521e3964608ea530a6ef5ffe3ece52688699f80ff1b", // node 4 - RPC aptos_primary_linkpool
		"0x47761f0c0dadb79b2fc1d3b0d975a2cb8ff906a809a97aadc3cec584d1da2282", // node 5 - RPC aptos_primary_quiknode
		"0x24b3b178bd8408c5e5f3d5af5fe3395018cd190395037c054edd99ca0febc82f", // node 6 - RPC aptos_primary_p2pify
		"0xa688106692e1b14853f1bf7ea6e84bfaa65f71adfc4bfd2a3a746367fec210fa", // node 7 - RPC aptos_primary_linkpool
		"0x0e861e0f3abf2c0b0842b1d1c939c42cf5b121eaf296d4f9943c0cc18ac1a14e", // node 8 - RPC aptos_primary_quiknode
		"0xe9f43f65ee39887ef15557194154942fcab8f11f5c8e73990f4523435435f846", // node 9 - RPC aptos_primary_p2pify
	},
	"prod-testnet-zone-b": {
		"0x771ed5b608be49fb9ae805884543d9fbaedbaf7011e853a0e3c7290b61de1953",
		"0x1b2b488dad2e2bacd396084f88f20da7688ac270b4cb8ea5190ec9a1146e9898",
		"0x6956bfe2f588bc278aa6701dd03cb9f8e659081be2bd5af05acb7ef476918fb2",
		"0x7e715f84a44b6dbbf3714c7cc3475e78464a072079eaf2d6f8353fddea969996",
		"0x0770df60ea0df993eeee293398db59e07f6b46f6a5c1b2e3e54dd4269aaa6129",
		"0xc161409c1790a673afe65db17e71a7ba2768e34c66fb1ecfac9617633a09d42b",
		"0xf7a988f365327e7ee00b862f991ca4cb0011fab93a192358e11fd6d7870e7ce4",
		"0xbfd481c87534aac0895fe1746531dd492c9321e02f7d830e922b166d4d6a511b",
		"0x18180f506ae3b9a68155c66d1bb944d49ea3ab6eb6b69e7a0aa5ec4cea0c81bd",
		"0xc85da50f7ef7a36752772cad11a26a6b77b65ce4749bc8106132e1102ab8ba04",
	},
	"mainnet": {
		"0x0ccb64f4a24f3791752ea3bad8d2e9dd451e7347b8975c263c02b2180d31b2b9", // writer_1-node-chainlayer
		"0x080e899c2f3f5fb4f207953d9ecdedf86faa940756c6e4f47c55c45d8c1ae7b9", // writer_1-node-chainlinklabs
		"0x4392652252a8289dcbe820a137c624408dbeec420cda4e2a7c5a3662cb956484", // writer_1-node-dextrac
		"0xfb7ebc84ce674c3c1f7a789a30084d2227056982fb430dfd8b18c8f7737f4f57", // writer_1-node-fiews
		"0xe7f459b0e6ceb3c3f35b6e8a4647eb6879bf21c78ebc0bee63cc0c6ff0cca276", // writer_1-node-inotel
		"0xaba7a83b8aa67be1cf726d250abe687629c875d04c57de238bcc72c208bffce8", // writer_1-node-linkpool
		"0x03caaf3f4e2b1510592890efcdd5e6ca6c61abe4238de323881ae768a0a39d73", // writer_1-node-linkriver
		"0x5c013a770992f487e1e2f31e2b56b3f1655c54bae7ab6ff44c49b9f42bb9e3ec", // writer_1-node-piertwo
		"0x9f303c5d6473437e4386318118020ff32ad09a97091a4470fa8b0ebe1dd67974", // writer_1-node-simplystaking
	},
}

func GetAccountsByEnvironment(environment string) []string {
	accounts, ok := accountsByEnvironment[environment]

	if !ok {
		log.Fatalf("Invalid environment: %s. Valid options are: staging, prod-testnet, mainnet", environment)
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
	}

	network, exists := environmentNetworks[environment]
	if !exists {
		log.Fatalf("Unsupported environment: %s", environment)
	}

	return network
}
