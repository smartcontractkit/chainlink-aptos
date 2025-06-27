module ccip::merkle_proof;

use sui::hash;

const LEAF_DOMAIN_SEPARATOR: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
const INTERNAL_DOMAIN_SEPARATOR: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000001";

const EVectorLengthMismatch: u64 = 1;

public fun leaf_domain_separator(): vector<u8> {
    LEAF_DOMAIN_SEPARATOR
}

public fun merkle_root(leaf: vector<u8>, proofs: vector<vector<u8>>): vector<u8> {
    proofs.fold!(leaf, |acc, proof| hash_pair(acc, proof))
}

public fun vector_u8_gt(a: &vector<u8>, b: &vector<u8>): bool {
    let len = a.length();
    assert!(
        len == b.length(), EVectorLengthMismatch
    );

    let mut i = 0;
    // compare each byte until not equal
    while (i < len) {
        let byte_a = a[i];
        let byte_b = b[i];
        if (byte_a > byte_b) {
            return true
        } else if (byte_a < byte_b) {
            return false
        };
        i = i + 1;
    };

    // vectors are equal, a == b
    false
}

fun hash_internal_node(left: vector<u8>, right: vector<u8>): vector<u8> {
    let mut data = INTERNAL_DOMAIN_SEPARATOR;
    data.append(left);
    data.append(right);
    hash::keccak256(&data)
}

/// Hashes a pair of byte vectors, ordering them lexographically
fun hash_pair(a: vector<u8>, b: vector<u8>): vector<u8> {
    if (!vector_u8_gt(&a, &b)) {
        hash_internal_node(a, b)
    } else {
        hash_internal_node(b, a)
    }
}
