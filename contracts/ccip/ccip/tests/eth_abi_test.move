#[test_only]
module ccip::eth_abi_test {
    use ccip::eth_abi;

    #[test]
    public fun test_encode_u256() {
        let out: vector<u8> = vector[];
        let value: u256 = 0xaaaaee;
        eth_abi::encode_u256(&mut out, value);

        assert!(out.length() == 32);

        // Ensure the output is in big-endian format
        assert!(out[31] == 0xee, 1110000);
        assert!(out[30] == 0xaa, 1110001);
        assert!(out[29] == 0xaa, 1110002);
        assert!(out[28] == 0x00, 1110004);
        assert!(out[0] == 0x00, 1110005);
    }

    #[test]
    public fun test_encode_empty() {
        let out: vector<u8> = vector[];
        let value: vector<u8> = vector[];
        eth_abi::encode_bytes(&mut out, value);
        assert!(out.length() == 32);
    }

    #[test]
    public fun test_encode_bytes() {
        let out: vector<u8> = vector[];
        let value: vector<u8> = vector[0x01];
        eth_abi::encode_bytes(&mut out, value);

        assert!(out.length() == 64);
    }

    #[test]
    public fun test_encode_bytes_exactly_32_bytes() {
        let out: vector<u8> = vector[];

        let value: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        // Length 32 should be 64 bytes
        assert!(value.length() == 32);

        eth_abi::encode_bytes(&mut out, value);

        assert!(out.length() == 64);

        // If we add one more byte, it should be 33 bytes which takes three 32-byte slots
        out = vector[];
        value.push_back(0x01);

        // Length 33 should be 96 bytes
        assert!(value.length() == 33);

        eth_abi::encode_bytes(&mut out, value);

        assert!(out.length() == 96);
    }
}
