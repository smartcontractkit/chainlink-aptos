// module to do the equivalent packing as ethereum's abi.encode and abi.encodePacked
module ccip::eth_abi {
    use std::bcs;
    use std::error;
    use std::from_bcs;
    use std::vector;

    const ENCODED_BOOL_FALSE: vector<u8> = vector[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0
    ];
    const ENCODED_BOOL_TRUE: vector<u8> = vector[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1
    ];

    const E_OUT_OF_BYTES: u64 = 1;
    const E_INVALID_BYTES32: u64 = 2;
    const E_INVALID_ADDRESS: u64 = 3;
    const E_INVALID_BOOL: u64 = 4;
    const E_INVALID_SELECTOR: u64 = 5;
    const E_INVALID_U256_LENGTH: u64 = 6;

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

    public fun encode_bool(out: &mut vector<u8>, value: bool) {
        vector::append(out, if (value) ENCODED_BOOL_TRUE
        else ENCODED_BOOL_FALSE)
    }

    public inline fun encode_bytes32(
        out: &mut vector<u8>, value: vector<u8>
    ) {
        assert!(vector::length(&value) <= 32, 600001);
        let padding_len = 32 - vector::length(&value);
        for (i in 0..padding_len) {
            vector::push_back(out, 0);
        };
        vector::append(out, value)
    }

    public inline fun encode_bytes(out: &mut vector<u8>, value: vector<u8>) {
        encode_u256(out, (vector::length(&value) as u256));

        vector::append(out, value);
        let padding_len = 32 - (vector::length(&value) % 32);
        for (i in 0..padding_len) {
            vector::push_back(out, 0);
        }
    }

    public fun encode_selector(out: &mut vector<u8>, value: vector<u8>) {
        assert!(vector::length(&value) == 4, error::invalid_argument(E_INVALID_SELECTOR));
        vector::append(out, value);
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
            cur + 32 <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        // Verify first 12 bytes are zero
        for (i in 0..12) {
            assert!(
                *vector::borrow(data, cur + i) == 0,
                error::invalid_argument(E_INVALID_ADDRESS)
            );
        };

        // Extract last 20 bytes for address
        let addr_bytes = vector::slice(data, cur + 12, cur + 32);
        stream.cur = cur + 32;

        from_bcs::to_address(addr_bytes)
    }

    public fun decode_u256(stream: &mut ABIStream): u256 {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + 32 <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        let value_bytes = vector::slice(data, cur, cur + 32);
        // Convert from big endian to little endian
        vector::reverse(&mut value_bytes);

        stream.cur = cur + 32;
        from_bcs::to_u256(value_bytes)
    }

    public fun decode_u8(stream: &mut ABIStream): u8 {
        (decode_u256(stream) as u8)
    }

    public fun decode_u32(stream: &mut ABIStream): u32 {
        (decode_u256(stream) as u32)
    }

    public fun decode_u64(stream: &mut ABIStream): u64 {
        (decode_u256(stream) as u64)
    }

    public fun decode_bool(stream: &mut ABIStream): bool {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + 32 <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        let value = vector::slice(data, cur, cur + 32);
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
            cur + 32 <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        let bytes = vector::slice(data, cur, cur + 32);
        stream.cur = cur + 32;
        bytes
    }

    public fun decode_bytes(stream: &mut ABIStream): vector<u8> {
        // First read length as u256
        let length = (decode_u256(stream) as u64);

        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + length <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        let bytes = vector::slice(data, cur, cur + length);

        // Skip padding bytes
        let padding_len = if (length % 32 == 0) { 0 }
        else {
            32 - (length % 32)
        };
        stream.cur = cur + length + padding_len;

        bytes
    }

    public inline fun decode_vector<E>(
        stream: &mut ABIStream, elem_decoder: |&mut ABIStream| E
    ): vector<E> {
        let len = decode_u256(stream);
        let v = vector::empty();

        for (i in 0..len) {
            vector::push_back(&mut v, elem_decoder(stream));
        };

        v
    }

    public fun decode_u256_value(value_bytes: vector<u8>): u256 {
        assert!(
            vector::length(&value_bytes) == 32,
            error::invalid_argument(E_INVALID_U256_LENGTH)
        );
        vector::reverse(&mut value_bytes);
        from_bcs::to_u256(value_bytes)
    }
}
