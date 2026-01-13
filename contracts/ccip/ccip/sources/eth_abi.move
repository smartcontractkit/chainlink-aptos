// module to do the equivalent packing as ethereum's abi.encode and abi.encodePacked
module ccip::eth_abi {
    use std::bcs;
    use std::error;
    use std::from_bcs;
    use std::vector;

    const ENCODED_BOOL_FALSE: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const ENCODED_BOOL_TRUE: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    const E_OUT_OF_BYTES: u64 = 1;
    const E_INVALID_ADDRESS: u64 = 2;
    const E_INVALID_BOOL: u64 = 3;
    const E_INVALID_SELECTOR: u64 = 4;
    const E_INVALID_U256_LENGTH: u64 = 5;
    const E_INTEGER_OVERFLOW: u64 = 6;
    const E_INVALID_BYTES32_LENGTH: u64 = 7;

    public inline fun encode_address(out: &mut vector<u8>, value: address) {
        out.append(bcs::to_bytes(&value))
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
        value_bytes.reverse();
        out.append(value_bytes)
    }

    public fun encode_bool(out: &mut vector<u8>, value: bool) {
        out.append(if (value) ENCODED_BOOL_TRUE else ENCODED_BOOL_FALSE)
    }

    /// For numeric types (address, uint, int) - left padded with zeros
    public inline fun encode_left_padded_bytes32(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        assert!(value.length() <= 32, error::invalid_argument(E_INVALID_U256_LENGTH));

        let padding_len = 32 - value.length();
        for (i in 0..padding_len) {
            out.push_back(0);
        };
        out.append(value);
    }

    /// For byte array types (bytes32, bytes4, etc.) - right padded with zeros
    public inline fun encode_right_padded_bytes32(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        assert!(value.length() <= 32, E_INVALID_BYTES32_LENGTH);

        out.append(value);
        let padding_len = 32 - value.length();
        for (i in 0..padding_len) {
            out.push_back(0);
        };
    }

    public inline fun encode_bytes(out: &mut vector<u8>, value: vector<u8>) {
        encode_u256(out, (value.length() as u256));

        out.append(value);
        if (value.length() % 32 != 0) {
            let padding_len = 32 - (value.length() % 32);
            for (i in 0..padding_len) {
                out.push_back(0);
            }
        }
    }

    public fun encode_selector(out: &mut vector<u8>, value: vector<u8>) {
        assert!(value.length() == 4, error::invalid_argument(E_INVALID_SELECTOR));
        out.append(value);
    }

    public inline fun encode_packed_address(
        out: &mut vector<u8>, value: address
    ) {
        out.append(bcs::to_bytes(&value))
    }

    public inline fun encode_packed_bytes(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        out.append(value)
    }

    public inline fun encode_packed_bytes32(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        assert!(value.length() <= 32, E_INVALID_BYTES32_LENGTH);

        out.append(value);
        let padding_len = 32 - value.length();
        for (i in 0..padding_len) {
            out.push_back(0);
        };
    }

    public inline fun encode_packed_u8(out: &mut vector<u8>, value: u8) {
        out.push_back(value)
    }

    public inline fun encode_packed_u32(out: &mut vector<u8>, value: u32) {
        let value_bytes = bcs::to_bytes(&value);
        // little endian to big endian
        value_bytes.reverse();
        out.append(value_bytes)
    }

    public inline fun encode_packed_u64(out: &mut vector<u8>, value: u64) {
        let value_bytes = bcs::to_bytes(&value);
        // little endian to big endian
        value_bytes.reverse();
        out.append(value_bytes)
    }

    public inline fun encode_packed_u256(out: &mut vector<u8>, value: u256) {
        let value_bytes = bcs::to_bytes(&value);
        // little endian to big endian
        value_bytes.reverse();
        out.append(value_bytes)
    }

    struct ABIStream has drop {
        data: vector<u8>,
        cur: u64
    }

    public fun new_stream(data: vector<u8>): ABIStream {
        ABIStream { data, cur: 0 }
    }

    public fun decode_address(stream: &mut ABIStream): address {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + 32 <= data.length(), error::out_of_range(E_OUT_OF_BYTES)
        );

        // Verify first 12 bytes are zero
        for (i in 0..12) {
            assert!(
                data[cur + i] == 0, error::invalid_argument(E_INVALID_ADDRESS)
            );
        };

        // Extract last 20 bytes for address
        let addr_bytes = data.slice(cur + 12, cur + 32);
        stream.cur = cur + 32;

        from_bcs::to_address(addr_bytes)
    }

    public fun decode_u256(stream: &mut ABIStream): u256 {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + 32 <= data.length(), error::out_of_range(E_OUT_OF_BYTES)
        );

        let value_bytes = data.slice(cur, cur + 32);
        // Convert from big endian to little endian
        value_bytes.reverse();

        stream.cur = cur + 32;
        from_bcs::to_u256(value_bytes)
    }

    public fun decode_u8(stream: &mut ABIStream): u8 {
        let value = decode_u256(stream);
        assert!(value <= 0xFF, error::invalid_argument(E_INTEGER_OVERFLOW));
        (value as u8)
    }

    public fun decode_u32(stream: &mut ABIStream): u32 {
        let value = decode_u256(stream);
        assert!(value <= 0xFFFFFFFF, error::invalid_argument(E_INTEGER_OVERFLOW));
        (value as u32)
    }

    public fun decode_u64(stream: &mut ABIStream): u64 {
        let value = decode_u256(stream);
        assert!(value <= 0xFFFFFFFFFFFFFFFF, error::invalid_argument(E_INTEGER_OVERFLOW));
        (value as u64)
    }

    public fun decode_bool(stream: &mut ABIStream): bool {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + 32 <= data.length(), error::out_of_range(E_OUT_OF_BYTES)
        );

        let value = data.slice(cur, cur + 32);
        stream.cur = cur + 32;

        if (value == ENCODED_BOOL_FALSE) { false }
        else if (value == ENCODED_BOOL_TRUE) { true }
        else {
            abort error::invalid_argument(E_INVALID_BOOL)
        }
    }

    public fun decode_bytes32(stream: &mut ABIStream): vector<u8> {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + 32 <= data.length(), error::out_of_range(E_OUT_OF_BYTES)
        );

        let bytes = data.slice(cur, cur + 32);
        stream.cur = cur + 32;
        bytes
    }

    public fun decode_bytes(stream: &mut ABIStream): vector<u8> {
        // First read length as u256
        let length = (decode_u256(stream) as u64);

        let padding_len = if (length % 32 == 0) { 0 }
        else {
            32 - (length % 32)
        };

        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + length + padding_len <= data.length(),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        let bytes = data.slice(cur, cur + length);

        // Skip padding bytes
        stream.cur = cur + length + padding_len;

        bytes
    }

    public inline fun decode_vector<E>(
        stream: &mut ABIStream, elem_decoder: |&mut ABIStream| E
    ): vector<E> {
        let len = decode_u256(stream);
        let v = vector::empty();

        for (i in 0..len) {
            v.push_back(elem_decoder(stream));
        };

        v
    }

    public fun decode_u256_value(value_bytes: vector<u8>): u256 {
        assert!(
            value_bytes.length() == 32,
            error::invalid_argument(E_INVALID_U256_LENGTH)
        );
        value_bytes.reverse();
        from_bcs::to_u256(value_bytes)
    }
}
