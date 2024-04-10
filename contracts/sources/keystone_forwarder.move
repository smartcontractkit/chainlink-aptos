module chainlink::keystone_forwarder {
	const E_INVALID_DATA_LENGTH: u64 = 0;

	fun transmit(target_address: address, data: vector<u8>, signatures: vector<u8>) {
		// assert!(data.length > 4 + 64, E_INVALID_DATA_LENGTH);
		target_address::test();
	}
}
