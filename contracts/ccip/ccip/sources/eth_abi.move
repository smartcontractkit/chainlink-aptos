// module to do the equivalent packing as ethereum's abi.encode and abi.encodePacked
module ccip::eth_abi;

use sui::address;
use sui::bcs;

const E_OUT_OF_BYTES: u64 = 1;
const E_INVALID_ADDRESS: u64 = 2;
const E_INVALID_BOOL: u64 = 3;
const E_INVALID_SELECTOR: u64 = 4;
const E_INVALID_U256_LENGTH: u64 = 5;
const E_INVALID_BYTES32_LENGTH: u64 = 6;
const E_INTEGER_OVERFLOW: u64 = 7;

const ENCODED_BOOL_FALSE: vector<u8> = vector[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];
const ENCODED_BOOL_TRUE: vector<u8> = vector[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
];

public fun encode_object_id(out: &mut vector<u8>, value: object::ID) {
    encode_address(out, object::id_to_address(&value))
}

public fun encode_address(out: &mut vector<u8>, value: address) {
    out.append(bcs::to_bytes(&value));
}

public fun encode_u8(out: &mut vector<u8>, value: u8) {
    encode_u256(out, value as u256);
}

public fun encode_u32(out: &mut vector<u8>, value: u32) {
    encode_u256(out, value as u256)
}

public fun encode_u64(out: &mut vector<u8>, value: u64) {
    encode_u256(out, value as u256)
}

public fun encode_u256(out: &mut vector<u8>, value: u256) {
    let mut value_bytes = bcs::to_bytes(&value);
    // little endian to big endian
    value_bytes.reverse();
    out.append(value_bytes);
}

public fun encode_bool(out: &mut vector<u8>, value: bool) {
    out.append(if (value) ENCODED_BOOL_TRUE
    else ENCODED_BOOL_FALSE);
}

public fun encode_left_padded_bytes32(
    out: &mut vector<u8>, value: vector<u8>
) {
    assert!(value.length() <= 32, E_INVALID_U256_LENGTH);

    let padding_len = 32 - value.length();
    let mut i = 0;
    while (i < padding_len) {
        out.push_back(0);
        i = i + 1;
    };
    out.append(value);
}

/// For byte array types (bytes32, bytes4, etc.) - right padded with zeros
public fun encode_right_padded_bytes32(
    out: &mut vector<u8>, value: vector<u8>
) {
    assert!(value.length() <= 32, E_INVALID_BYTES32_LENGTH);

    out.append(value);
    let padding_len = 32 - value.length();
    let mut i = 0;
    while (i < padding_len) {
        out.push_back(0);
        i = i + 1;
    };
}

public fun encode_bytes(out: &mut vector<u8>, value: vector<u8>) {
    encode_u256(out, (value.length() as u256));

    out.append(value);
    if (value.length() % 32 != 0) {
        let padding_len = 32 - (value.length() % 32);
        let mut i = 0;
        while (i < padding_len) {
            out.push_back(0);
            i = i + 1;
        };
    };
}

public fun encode_selector(out: &mut vector<u8>, value: vector<u8>) {
    assert!(value.length() == 4, E_INVALID_SELECTOR);
    out.append(value);
}

// TODO: not used onchain. verify if used offchain
public fun encode_packed_address(
    out: &mut vector<u8>, value: address
) {
    out.append(bcs::to_bytes(&value));
}

public fun encode_packed_bytes(
    out: &mut vector<u8>, value: vector<u8>
) {
    out.append(value);
}

public fun encode_packed_bytes32(
    out: &mut vector<u8>, value: vector<u8>
) {
    assert!(value.length() <= 32, E_INVALID_BYTES32_LENGTH);
    out.append(value);

    let padding_len = 32 - value.length();
    let mut i = 0;
    while (i < padding_len) {
        out.push_back(0);
        i = i + 1;
    };
}

public fun encode_packed_u8(out: &mut vector<u8>, value: u8) {
    out.push_back(value);
}

public fun encode_packed_u32(out: &mut vector<u8>, value: u32) {
    let mut value_bytes = bcs::to_bytes(&value);
    // little endian to big endian
    value_bytes.reverse();
    out.append(value_bytes);
}

public fun encode_packed_u64(out: &mut vector<u8>, value: u64) {
    let mut value_bytes = bcs::to_bytes(&value);
    // little endian to big endian
    value_bytes.reverse();
    out.append(value_bytes);
}

public fun encode_packed_u256(out: &mut vector<u8>, value: u256) {
    let mut value_bytes = bcs::to_bytes(&value);
    // little endian to big endian
    value_bytes.reverse();
    out.append(value_bytes);
}

// ABIStream won't be published. no need to add a key
public struct ABIStream has drop {
    data: vector<u8>,
    cur: u64
}

#[test_only]
public fun get_cur(stream: &ABIStream): u64 {
    stream.cur
}

public fun new_stream(data: vector<u8>): ABIStream {
    ABIStream { data, cur: 0 }
}

public fun decode_address(stream: &mut ABIStream): address {
    let data = &stream.data;
    let cur = stream.cur;

    assert!(
        cur + 32 <= data.length(),
        E_OUT_OF_BYTES
    );

    // Verify first 12 bytes are zero
    // This is to decode Ethereum address not Sui address
    let mut i = 0;
    let mut value_bytes = vector[];
    while (i < 12) {
        assert!(
            data[cur + i] == 0,
            E_INVALID_ADDRESS
        );
        value_bytes.push_back(0);
        i = i + 1;
    };

    // add the remaining 20 bytes
    while (i < 32) {
        value_bytes.push_back(data[cur + i]);
        i = i + 1;
    };
    stream.cur = cur + 32;

    address::from_bytes(value_bytes)
}

public fun decode_u256_value(mut value_bytes: vector<u8>): u256 {
    assert!(
        value_bytes.length() == 32,
        E_INVALID_U256_LENGTH
    );
    value_bytes.reverse();

    // Deserialize to u256
    bcs::peel_u256(&mut bcs::new(value_bytes))
}

public fun decode_u256(stream: &mut ABIStream): u256 {
    let data = &stream.data;
    let cur = stream.cur;

    assert!(
        cur + 32 <= data.length(),
        E_OUT_OF_BYTES
    );

    let mut value_bytes = slice(data, cur, 32);
    // Convert from big endian to little endian
    value_bytes.reverse();

    stream.cur = cur + 32;
    bcs::peel_u256(&mut bcs::new(value_bytes))
}

/// Returns a new vector containing `len` elements from `vec`
/// starting at index `start`. Panics if `start + len` exceeds the vector length.
public(package) fun slice<T: copy>(vec: &vector<T>, start: u64, len: u64): vector<T> {
    let vec_len = vec.length();
    // Ensure we have enough elements for the slice.
    assert!(start + len <= vec_len, E_OUT_OF_BYTES);
    let mut new_vec = vector::empty<T>();
    let mut i = start;
    while (i < start + len) {
        // Copy each element from the original vector into the new vector.
        new_vec.push_back(vec[i]);
        i = i + 1;
    };
    new_vec
}

public fun decode_u8(stream: &mut ABIStream): u8 {
    let value = decode_u256(stream);
    assert!(value <= 0xFF, E_INTEGER_OVERFLOW);
    (value as u8)
}

public fun decode_u32(stream: &mut ABIStream): u32 {
    let value = decode_u256(stream);
    assert!(value <= 0xFFFFFFFF, E_INTEGER_OVERFLOW);
    (value as u32)
}

public fun decode_u64(stream: &mut ABIStream): u64 {
    let value = decode_u256(stream);
    assert!(value <= 0xFFFFFFFFFFFFFFFF, E_INTEGER_OVERFLOW);
    (value as u64)
}

public fun decode_bool(stream: &mut ABIStream): bool {
    let data = &stream.data;
    let cur = stream.cur;

    assert!(
        cur + 32 <= data.length(),
        E_OUT_OF_BYTES
    );

    let value = slice(data, cur, 32);
    stream.cur = cur + 32;

    if (value == ENCODED_BOOL_FALSE) { false }
    else if (value == ENCODED_BOOL_TRUE) { true }
    else {
        abort E_INVALID_BOOL
    }
}

public macro fun decode_vector<$E>(
    $stream: &mut ABIStream, $f: |&mut ABIStream| -> $E
): vector<$E> {
    let len = decode_u256($stream);
    let mut v = vector[];
    let mut i = 0;

    while (i < len) {
        v.push_back($f($stream));
        i = i + 1;
    };

    v
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
        E_OUT_OF_BYTES
    );

    let bytes = slice(data, cur, length);

    stream.cur = cur + length + padding_len;

    bytes
}

public fun decode_bytes32(stream: &mut ABIStream): vector<u8> {
    let data = &stream.data;
    let cur = stream.cur;

    assert!(
        cur + 32 <= data.length(),
        E_OUT_OF_BYTES
    );

    let bytes = slice(data, cur, 32);
    stream.cur = cur + 32;
    bytes
}
