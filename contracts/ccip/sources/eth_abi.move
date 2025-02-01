// module to do the equivalent packing as ethereum's abi.encode and abi.encodePacked
module ccip::eth_abi {
    use std::bcs;
    use std::from_bcs;
    use std::vector;

    const E_INVALID_BYTES32: u64 = 1;

    public inline fun encode_address(out: &mut vector<u8>, value: address) {
        vector::append(out, bcs::to_bytes(&value))
    }

    public inline fun encode_u8(out: &mut vector<u8>, value: u8) {
        encode_u256(out, value as u256);
    }

    public inline fun encode_u32(out: &mut vector<u8>, value: u32) {
        encode_u256(out, value as u256)
    }

    public inline fun encode_u64(out: &mut vector<u8>, value: u64) {
        encode_u256(out, value as u256)
    }

    public inline fun encode_u256(out: &mut vector<u8>, value: u256) {
        let value_bytes = bcs::to_bytes(&value);
        // little endian to big endian
        vector::reverse(&mut value_bytes);
        vector::append(out, value_bytes)
    }

    public inline fun encode_bytes32(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        assert!(vector::length(&value) <= 32, 600001);
        let padding_len = 32 - vector::length(&value);
        let i = 0;
        while (i < padding_len) {
            vector::push_back(out, 0);
            i = i + 1;
        };
        vector::append(out, value)
    }

    public inline fun encode_bytes(out: &mut vector<u8>, value: vector<u8>) {
        encode_u256(out, (vector::length(&value) as u256));

        vector::append(out, value);
        let padding_len = 32 - (vector::length(&value) % 32);
        let i = 0;
        while (i < padding_len) {
            vector::push_back(out, 0);
            i = i + 1;
        }
    }

    public inline fun encode_packed_address(
        out: &mut vector<u8>, value: address
    ) {
        vector::append(out, bcs::to_bytes(&value))
    }

    public inline fun encode_packed_bytes(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        vector::append(out, value)
    }

    public inline fun encode_packed_bytes32(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        assert!(vector::length(&value) <= 32, 600002);
        vector::append(out, value)
    }

    public inline fun encode_packed_u8(out: &mut vector<u8>, value: u8) {
        vector::push_back(out, value)
    }

    public inline fun encode_packed_u32(out: &mut vector<u8>, value: u32) {
        let value_bytes = bcs::to_bytes(&value);
        // little endian to big endian
        vector::reverse(&mut value_bytes);
        vector::append(out, value_bytes)
    }

    public inline fun encode_packed_u64(out: &mut vector<u8>, value: u64) {
        let value_bytes = bcs::to_bytes(&value);
        // little endian to big endian
        vector::reverse(&mut value_bytes);
        vector::append(out, value_bytes)
    }

    public inline fun encode_packed_u256(out: &mut vector<u8>, value: u256) {
        let value_bytes = bcs::to_bytes(&value);
        // little endian to big endian
        vector::reverse(&mut value_bytes);
        vector::append(out, value_bytes)
    }

    public inline fun decode_u256(value_bytes: vector<u8>): u256 {
        // big endian to little endian
        vector::reverse(&mut value_bytes);
        from_bcs::to_u256(value_bytes)
    }
}
