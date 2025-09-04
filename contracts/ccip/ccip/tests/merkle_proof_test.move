#[test_only]
module ccip::merkle_proof_test {
    use ccip::merkle_proof;
    use std::aptos_hash;

    #[test]
    fun test_leaf_domain_separator() {
        let expected =
            x"0000000000000000000000000000000000000000000000000000000000000000";
        let actual = merkle_proof::leaf_domain_separator();
        assert!(actual == expected, 1);
    }

    #[test]
    fun test_merkle_root_empty_proofs() {
        let leaf = b"hello";
        let proofs = vector[];
        let root = merkle_proof::merkle_root(leaf, proofs);
        // With empty proofs, root should be the leaf itself
        assert!(root == b"hello", 2);
    }

    #[test]
    fun test_merkle_root_single_proof() {
        let leaf = x"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let proof = x"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let proofs = vector[proof];

        let root = merkle_proof::merkle_root(leaf, proofs);

        // The root should be the hash of the leaf and proof
        // Since leaf < proof lexicographically, it should be hash_internal_node(leaf, proof)
        let expected_data =
            x"0000000000000000000000000000000000000000000000000000000000000001"; // INTERNAL_DOMAIN_SEPARATOR
        expected_data.append(leaf);
        expected_data.append(proof);
        let expected = aptos_hash::keccak256(expected_data);

        assert!(root == expected, 3);
    }

    #[test]
    fun test_merkle_root_multiple_proofs() {
        let leaf = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let proof1 = x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let proof2 = x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let proofs = vector[proof1, proof2];

        let root = merkle_proof::merkle_root(leaf, proofs);

        // Should apply proofs sequentially
        // First: hash_pair(leaf, proof1) - since leaf < proof1, it should be hash_internal_node(leaf, proof1)
        let step1_data =
            x"0000000000000000000000000000000000000000000000000000000000000001"; // INTERNAL_DOMAIN_SEPARATOR
        step1_data.append(leaf);
        step1_data.append(proof1);
        let step1_hash = aptos_hash::keccak256(step1_data);

        // Second: hash_pair(step1_hash, proof2) - need to check which is lexicographically smaller
        // Let's calculate both possibilities to see which should be the expected result
        let step2_data =
            x"0000000000000000000000000000000000000000000000000000000000000001"; // INTERNAL_DOMAIN_SEPARATOR
        if (!merkle_proof::vector_u8_gt(&step1_hash, &proof2)) {
            // step1_hash <= proof2, so hash_internal_node(step1_hash, proof2)
            step2_data.append(step1_hash);
            step2_data.append(proof2);
        } else {
            // step1_hash > proof2, so hash_internal_node(proof2, step1_hash)
            step2_data.append(proof2);
            step2_data.append(step1_hash);
        };
        let expected = aptos_hash::keccak256(step2_data);

        assert!(root == expected, 4);
    }

    #[test]
    #[expected_failure(abort_code = 65537, location = ccip::merkle_proof)]
    fun test_vector_u8_gt_different_lengths_should_abort() {
        let a = vector[1, 2, 3];
        let b = vector[1, 2];
        // This should abort due to length mismatch
        merkle_proof::vector_u8_gt(&a, &b);
    }

    #[test]
    fun test_vector_u8_gt_first_greater() {
        let a = vector[2, 1, 1];
        let b = vector[1, 2, 2];
        assert!(merkle_proof::vector_u8_gt(&a, &b) == true, 5);
    }

    #[test]
    fun test_vector_u8_gt_second_greater() {
        let a = vector[1, 1, 1];
        let b = vector[2, 0, 0];
        assert!(merkle_proof::vector_u8_gt(&a, &b) == false, 6);
    }

    #[test]
    fun test_vector_u8_gt_equal_vectors() {
        let a = vector[1, 2, 3];
        let b = vector[1, 2, 3];
        assert!(merkle_proof::vector_u8_gt(&a, &b) == false, 7);
    }

    #[test]
    fun test_vector_u8_gt_later_byte_differs() {
        let a = vector[1, 2, 4];
        let b = vector[1, 2, 3];
        assert!(merkle_proof::vector_u8_gt(&a, &b) == true, 8);
    }

    #[test]
    fun test_vector_u8_gt_empty_vectors() {
        let a = vector[];
        let b = vector[];
        assert!(merkle_proof::vector_u8_gt(&a, &b) == false, 9);
    }

    #[test]
    fun test_merkle_root_proof_ordering() {
        // Test that the lexicographic ordering works correctly in hash_pair
        let leaf = x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let proof = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let proofs = vector[proof];

        let root = merkle_proof::merkle_root(leaf, proofs);

        // Since proof < leaf lexicographically, it should be hash_internal_node(proof, leaf)
        let expected_data =
            x"0000000000000000000000000000000000000000000000000000000000000001"; // INTERNAL_DOMAIN_SEPARATOR
        expected_data.append(proof); // proof comes first since it's smaller
        expected_data.append(leaf);
        let expected = aptos_hash::keccak256(expected_data);

        assert!(root == expected, 10);
    }

    #[test]
    fun test_merkle_root_with_identical_leaf_and_proof() {
        let leaf = x"1111111111111111111111111111111111111111111111111111111111111111";
        let proof = x"1111111111111111111111111111111111111111111111111111111111111111";
        let proofs = vector[proof];

        let root = merkle_proof::merkle_root(leaf, proofs);

        // Since leaf == proof, the order doesn't matter, but vector_u8_gt returns false for equal vectors
        // So it should be hash_internal_node(leaf, proof)
        let expected_data =
            x"0000000000000000000000000000000000000000000000000000000000000001"; // INTERNAL_DOMAIN_SEPARATOR
        expected_data.append(leaf);
        expected_data.append(proof);
        let expected = aptos_hash::keccak256(expected_data);

        assert!(root == expected, 11);
    }
}
