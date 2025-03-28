/// Copied and modified from: https://github.com/aptos-labs/aptos-core/blob/9baf39b6fba7812f09238c91973f61fd0955057c/aptos-move/move-examples/bcs-stream/sources/stream.move
///
/// This module enables the deserialization of BCS-formatted byte arrays into Move primitive types.
/// Deserialization Strategies:
/// - Per-Byte Deserialization: Employed for most types to ensure lower gas consumption, this method processes each byte
///   individually to match the length and type requirements of target Move types.
/// - Exception: For the `deserialize_address` function, the function-based approach from `aptos_std::from_bcs` is used
///   due to type constraints, even though it is generally more gas-intensive.
/// - This can be optimized further by introducing native vector slices.
/// Application:
/// - This deserializer is particularly valuable for processing BCS serialized data within Move modules,
///   especially useful for systems requiring cross-chain message interpretation or off-chain data verification.
module mcms::bcs_stream {
    use std::error;
    use std::vector;
    use std::option::{Self, Option};
    use std::string::{Self, String};

    use aptos_std::from_bcs;

    /// The data does not fit the expected format.
    const E_MALFORMED_DATA: u64 = 1;
    /// There are not enough bytes to deserialize for the given type.
    const E_OUT_OF_BYTES: u64 = 2;
    /// The stream has not been consumed.
    const E_NOT_CONSUMED: u64 = 3;

    struct BCSStream has drop {
        /// Byte buffer containing the serialized data.
        data: vector<u8>,
        /// Cursor indicating the current position in the byte buffer.
        cur: u64
    }

    /// Constructs a new BCSStream instance from the provided byte array.
    public fun new(data: vector<u8>): BCSStream {
        BCSStream { data, cur: 0 }
    }

    /// Asserts that the stream has been fully consumed.
    public fun assert_is_consumed(stream: &BCSStream) {
        assert!(
            stream.cur == vector::length(&stream.data),
            error::invalid_state(E_NOT_CONSUMED)
        );
    }

    /// Deserializes a ULEB128-encoded integer from the stream.
    /// In the BCS format, lengths of vectors are represented using ULEB128 encoding.
    public fun deserialize_uleb128(stream: &mut BCSStream): u64 {
        let res = 0;
        let shift = 0;

        while (stream.cur < vector::length(&stream.data)) {
            let byte = *vector::borrow(&stream.data, stream.cur);
            stream.cur = stream.cur + 1;

            let val = ((byte & 0x7f) as u64);
            if (((val << shift) >> shift) != val) {
                abort error::invalid_argument(E_MALFORMED_DATA)
            };
            res = res | (val << shift);

            if ((byte & 0x80) == 0) {
                if (shift > 0 && val == 0) {
                    abort error::invalid_argument(E_MALFORMED_DATA)
                };
                return res
            };

            shift = shift + 7;
            if (shift > 64) {
                abort error::invalid_argument(E_MALFORMED_DATA)
            };
        };

        abort error::out_of_range(E_OUT_OF_BYTES)
    }

    /// Deserializes a `bool` value from the stream.
    public fun deserialize_bool(stream: &mut BCSStream): bool {
        assert!(
            stream.cur < vector::length(&stream.data),
            error::out_of_range(E_OUT_OF_BYTES)
        );
        let byte = *vector::borrow(&stream.data, stream.cur);
        stream.cur = stream.cur + 1;
        if (byte == 0) { false }
        else if (byte == 1) { true }
        else {
            abort error::invalid_argument(E_MALFORMED_DATA)
        }
    }

    /// Deserializes an `address` value from the stream.
    /// 32-byte `address` values are serialized using little-endian byte order.
    /// This function utilizes the `to_address` function from the `aptos_std::from_bcs` module,
    /// because the Move type system does not permit per-byte referencing of addresses.
    public fun deserialize_address(stream: &mut BCSStream): address {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            cur + 32 <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );
        let res = from_bcs::to_address(vector::slice(data, cur, cur + 32));

        stream.cur = cur + 32;
        res
    }

    /// `u8` values are serialized using little-endian byte order.
    public fun deserialize_uint(stream: &mut BCSStream, bytes: u64): u256 {
        let data = &stream.data;
        let cur = stream.cur;

        assert!(
            bytes <= 32,
            error::invalid_argument(E_MALFORMED_DATA)
        );

        assert!(
            cur + bytes <= data.length(),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        let res = 0 as u256;
        for (i in 0..bytes) {
            res |=(data[cur + i] << (i * 8 as u8) as u256);
        };

        stream.cur += bytes;
        res
    }

    /// Deserializes a `u8` value from the stream.
    /// 1-byte `u8` values are serialized using little-endian byte order.
    public fun deserialize_u8(stream: &mut BCSStream): u8 {
        deserialize_uint(stream, 1) as u8
    }

    /// Deserializes a `u16` value from the stream.
    /// 2-byte `u16` values are serialized using little-endian byte order.
    public fun deserialize_u16(stream: &mut BCSStream): u16 {
        deserialize_uint(stream, 2) as u16
    }

    /// Deserializes a `u32` value from the stream.
    /// 4-byte `u32` values are serialized using little-endian byte order.
    public fun deserialize_u32(stream: &mut BCSStream): u32 {
        deserialize_uint(stream, 4) as u32
    }

    /// Deserializes a `u64` value from the stream.
    /// 8-byte `u64` values are serialized using little-endian byte order.
    public fun deserialize_u64(stream: &mut BCSStream): u64 {
        deserialize_uint(stream, 8) as u64
    }

    /// Deserializes a `u128` value from the stream.
    /// 16-byte `u128` values are serialized using little-endian byte order.
    public fun deserialize_u128(stream: &mut BCSStream): u128 {
        deserialize_uint(stream, 16) as u128
    }

    /// Deserializes a `u256` value from the stream.
    /// 32-byte `u256` values are serialized using little-endian byte order.
    public fun deserialize_u256(stream: &mut BCSStream): u256 {
        deserialize_uint(stream, 32)
    }

    /// Deserializes a `u256` value from the stream.
    public entry fun deserialize_u256_entry(data: vector<u8>, cursor: u64) {
        let stream = BCSStream { data, cur: cursor };
        deserialize_u256(&mut stream);
    }

    /// Deserializes an array of BCS deserializable elements from the stream.
    /// First, reads the length of the vector, which is in uleb128 format.
    /// After determining the length, it then reads the contents of the vector.
    /// The `elem_deserializer` lambda expression is used sequentially to deserialize each element of the vector.
    public inline fun deserialize_vector<E>(
        stream: &mut BCSStream, elem_deserializer: |&mut BCSStream| E
    ): vector<E> {
        let len = deserialize_uleb128(stream);
        let v = vector::empty();

        for (i in 0..len) {
            vector::push_back(&mut v, elem_deserializer(stream));
        };

        v
    }

    public fun deserialize_vector_u8(stream: &mut BCSStream): vector<u8> {
        let len = deserialize_uleb128(stream);
        let data = &mut stream.data;
        let cur = stream.cur;

        assert!(
            cur + len <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        // AIP-105 introduces vector::move_range to efficiently move a range of elements from one vector to another.
        let res = vector::trim(data, cur);
        stream.data = vector::trim(&mut res, len);
        stream.cur = 0;

        res
    }

    /// Deserializes utf-8 `String` from the stream.
    /// First, reads the length of the String, which is in uleb128 format.
    /// After determining the length, it then reads the contents of the String.
    public fun deserialize_string(stream: &mut BCSStream): String {
        let len = deserialize_uleb128(stream);
        let data = &mut stream.data;
        let cur = stream.cur;

        assert!(
            cur + len <= vector::length(data),
            error::out_of_range(E_OUT_OF_BYTES)
        );

        // AIP-105 introduces vector::move_range to efficiently move a range of elements from one vector to another.
        let res = vector::trim(data, cur);
        stream.data = vector::trim(&mut res, len);
        stream.cur = 0;

        string::utf8(res)
    }

    /// Deserializes `Option` from the stream.
    /// First, reads a single byte representing the presence (0x01) or absence (0x00) of data.
    /// After determining the presence of data, it then reads the actual data if present.
    /// The `elem_deserializer` lambda expression is used to deserialize the element contained within the `Option`.
    public inline fun deserialize_option<E>(
        stream: &mut BCSStream, elem_deserializer: |&mut BCSStream| E
    ): Option<E> {
        let is_data = deserialize_bool(stream);
        if (is_data) {
            option::some(elem_deserializer(stream))
        } else {
            option::none()
        }
    }
}
