/// The merkle_proof module provides functionality for verifying Merkle proofs.
module chainlink_ccip::merkle_proof {
    use std::vector;
    
    use sui::hash::{Self, keccak256};
    
    // Error codes
    const E_INVALID_PROOF: u64 = 1;
    
    /// Verifies a Merkle proof.
    /// `leaf` is the leaf node value.
    /// `proof` is the Merkle proof.
    /// `root` is the Merkle root.
    /// Returns true if the proof is valid.
    public fun verify(
        leaf: vector<u8>,
        proof: vector<vector<u8>>,
        root: vector<u8>
    ): bool {
        let computed_hash = leaf;
        
        let i = 0;
        let len = vector::length(&proof);
        
        while (i < len) {
            let proof_element = *vector::borrow(&proof, i);
            
            // Sort the hashes to match the expected order
            if (bytes_less_than(&computed_hash, &proof_element)) {
                computed_hash = concat_and_hash(&computed_hash, &proof_element);
            } else {
                computed_hash = concat_and_hash(&proof_element, &computed_hash);
            };
            
            i = i + 1;
        };
        
        computed_hash == root
    }
    
    /// Concatenates two byte arrays and computes the Keccak-256 hash.
    fun concat_and_hash(a: &vector<u8>, b: &vector<u8>): vector<u8> {
        let result = *a;
        vector::append(&mut result, *b);
        keccak256(&result)
    }
    
    /// Compares two byte arrays lexicographically.
    /// Returns true if a < b.
    fun bytes_less_than(a: &vector<u8>, b: &vector<u8>): bool {
        let a_len = vector::length(a);
        let b_len = vector::length(b);
        let min_len = if (a_len < b_len) { a_len } else { b_len };
        
        let i = 0;
        while (i < min_len) {
            let a_byte = *vector::borrow(a, i);
            let b_byte = *vector::borrow(b, i);
            
            if (a_byte < b_byte) {
                return true
            } else if (a_byte > b_byte) {
                return false
            };
            
            i = i + 1;
        };
        
        a_len < b_len
    }
    
    #[test]
    fun test_verify_valid_proof() {
        // Example values for testing
        let leaf = x"0000000000000000000000000000000000000000000000000000000000000001";
        let proof = vector[
            x"0000000000000000000000000000000000000000000000000000000000000002",
            x"0000000000000000000000000000000000000000000000000000000000000003"
        ];
        
        // Compute the expected root
        let hash1 = concat_and_hash(&leaf, &x"0000000000000000000000000000000000000000000000000000000000000002");
        let root = concat_and_hash(&hash1, &x"0000000000000000000000000000000000000000000000000000000000000003");
        
        // Verify the proof
        assert!(verify(leaf, proof, root), 0);
    }
    
    #[test]
    fun test_verify_invalid_proof() {
        // Example values for testing
        let leaf = x"0000000000000000000000000000000000000000000000000000000000000001";
        let proof = vector[
            x"0000000000000000000000000000000000000000000000000000000000000002",
            x"0000000000000000000000000000000000000000000000000000000000000003"
        ];
        
        // Invalid root
        let invalid_root = x"1111111111111111111111111111111111111111111111111111111111111111";
        
        // Verify the proof should fail
        assert!(!verify(leaf, proof, invalid_root), 0);
    }
}
