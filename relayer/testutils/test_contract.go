package testutils

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func GetTestContract(t *testing.T, moduleAddress string) ([]byte, []byte) {
	// returns the metadata and module bytecode for a counter test contract:
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
	moduleAddressStripped := moduleAddress
	if strings.HasPrefix(moduleAddressStripped, "0x") {
		moduleAddressStripped = moduleAddressStripped[2:]
	}
	moduleBytecodeHex := "a11ceb0b060000000901000202020403060f05151207273a0861200a8101050c8601560ddc0102000000010e0000020001000003020100000403010002060c050004060c05030301060c0107080007636f756e74657207436f756e74657209696e6372656d656e740e696e6372656d656e745f6d756c740a696e697469616c697a650576616c7565" + moduleAddressStripped + "00020105030001040100040c0b012a000c020a02100014060100000000000000160b020f0015020101040100040e0b012a000c040a041000140b020b0318160b040f0015020201040001050b0006000000000000000012002d0002000000"

	packageMetadataBytes, err := hex.DecodeString(packageMetadataHex)
	require.NoError(t, err)

	moduleBytecodeBytes, err := hex.DecodeString(moduleBytecodeHex)
	require.NoError(t, err)

	return packageMetadataBytes, moduleBytecodeBytes
}
