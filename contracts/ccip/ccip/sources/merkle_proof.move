module ccip::merkle_proof {
    use std::aptos_hash;
    use std::error;

    const LEAF_DOMAIN_SEPARATOR: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    const INTERNAL_DOMAIN_SEPARATOR: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000001";

    const E_VECTOR_LENGTH_MISMATCH: u64 = 1;

    public fun leaf_domain_separator(): vector<u8> {
        LEAF_DOMAIN_SEPARATOR
    }

    public fun merkle_root(leaf: vector<u8>, proofs: vector<vector<u8>>): vector<u8> {
        proofs.fold(leaf, |acc, proof| hash_pair(acc, proof))
    }

    public fun vector_u8_gt(a: &vector<u8>, b: &vector<u8>): bool {
        let len = a.length();
        assert!(len == b.length(), error::invalid_argument(E_VECTOR_LENGTH_MISMATCH));

        // compare each byte until not equal
        for (i in 0..len) {
            let byte_a = a[i];
            let byte_b = b[i];
            if (byte_a > byte_b) {
                return true
            } else if (byte_a < byte_b) {
                return false
            };
        };

        // vectors are equal, a == b
        false
    }

    /// Hashes two byte vectors using SHA3-256 after concatenating them with the internal domain separator
    inline fun hash_internal_node(left: vector<u8>, right: vector<u8>): vector<u8> {
        let data = INTERNAL_DOMAIN_SEPARATOR;
        data.append(left);
        data.append(right);
        aptos_hash::keccak256(data)
    }

    /// Hashes a pair of byte vectors, ordering them lexographically
    inline fun hash_pair(a: vector<u8>, b: vector<u8>): vector<u8> {
        if (!vector_u8_gt(&a, &b)) {
            hash_internal_node(a, b)
        } else {
            hash_internal_node(b, a)
        }
    }
}
