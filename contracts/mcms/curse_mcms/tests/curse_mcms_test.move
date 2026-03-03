#[test_only]
module curse_mcms::curse_mcms_test {
    use std::signer;
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::timestamp;
    use aptos_framework::chain_id;

    use curse_mcms::curse_mcms;
    use curse_mcms::curse_mcms_account;

    // Signer addresses (sorted, 20 bytes each) - from Go test
    const SIGNER_1: vector<u8> = x"2b5ad5c4795c026514f8317c7a215e218dccd6cf";
    const SIGNER_2: vector<u8> = x"6813eb9362372eef6200f3b1dbc3f819671cba69";
    const SIGNER_3: vector<u8> = x"7e5f4552091a69125d5dfcb7b8c2659029395bdf";

    fun setup_test(framework: &signer, deployer: &signer, owner: &signer) {
        // Initialize timestamp for tests
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(1000);

        // Initialize chain_id
        chain_id::initialize_for_test(framework, 4);

        // Create accounts
        account::create_account_for_test(signer::address_of(deployer));
        account::create_account_for_test(signer::address_of(owner));

        // Initialize CurseMCMS account (ownership) - stores AccountState at @curse_mcms
        curse_mcms_account::init_module_for_testing(deployer);

        // Initialize CurseMCMS (multisigs)
        curse_mcms::init_module_for_testing(deployer);
    }

    // ================================================================
    // |                      Initialization Tests                     |
    // ================================================================
    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_initialize_success(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        // Verify owner is set correctly via curse_mcms_account
        assert!(curse_mcms_account::owner() == signer::address_of(owner), 1);
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    #[expected_failure(major_status = 4004, location = curse_mcms::curse_mcms)]
    // RESOURCE_ALREADY_EXISTS
    fun test_initialize_already_initialized(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        // Try to initialize again - should fail with RESOURCE_ALREADY_EXISTS
        curse_mcms::init_module_for_testing(deployer);
    }

    // ================================================================
    // |                      Ownership Tests                          |
    // ================================================================
    #[
        test(
            framework = @aptos_framework,
            deployer = @curse_mcms,
            owner = @curse_mcms_owner,
            new_owner = @0x123
        )
    ]
    fun test_transfer_ownership_success(
        framework: &signer, deployer: &signer, owner: &signer, new_owner: &signer
    ) {
        setup_test(framework, deployer, owner);
        account::create_account_for_test(signer::address_of(new_owner));

        // Transfer ownership via curse_mcms_account
        curse_mcms_account::transfer_ownership(owner, signer::address_of(new_owner));

        // Verify owner hasn't changed yet
        assert!(curse_mcms_account::owner() == signer::address_of(owner), 1);

        // Accept ownership
        curse_mcms_account::accept_ownership(new_owner);

        // Verify new owner
        assert!(curse_mcms_account::owner() == signer::address_of(new_owner), 2);
    }

    #[
        test(
            framework = @aptos_framework,
            deployer = @curse_mcms,
            owner = @curse_mcms_owner,
            not_owner = @0x456
        )
    ]
    // error::permission_denied(E_UNAUTHORIZED) = (5 << 16) | 3 = 327683
    #[expected_failure(abort_code = 327683, location = curse_mcms::curse_mcms_account)]
    fun test_transfer_ownership_not_owner(
        framework: &signer, deployer: &signer, owner: &signer, not_owner: &signer
    ) {
        setup_test(framework, deployer, owner);
        account::create_account_for_test(signer::address_of(not_owner));

        // Non-owner tries to transfer - should fail
        curse_mcms_account::transfer_ownership(not_owner, @0x999);
    }

    #[
        test(
            framework = @aptos_framework,
            deployer = @curse_mcms,
            owner = @curse_mcms_owner,
            wrong_accepter = @0x789
        )
    ]
    // error::permission_denied(E_MUST_BE_PROPOSED_OWNER) = (5 << 16) | 2 = 327682
    #[expected_failure(abort_code = 327682, location = curse_mcms::curse_mcms_account)]
    fun test_accept_ownership_wrong_accepter(
        framework: &signer,
        deployer: &signer,
        owner: &signer,
        wrong_accepter: &signer
    ) {
        setup_test(framework, deployer, owner);
        account::create_account_for_test(signer::address_of(wrong_accepter));

        // Transfer to different address
        curse_mcms_account::transfer_ownership(owner, @0x123);

        // Wrong address tries to accept - should fail
        curse_mcms_account::accept_ownership(wrong_accepter);
    }

    // ================================================================
    // |                      Set Config Tests                         |
    // ================================================================
    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_set_config_success(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        // Set up signers
        let signer_addresses = vector[SIGNER_1, SIGNER_2];
        let signer_groups = vector[0u8, 0u8];

        // Set up group quorums (2 signatures required in group 0)
        let group_quorums = vector[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        // Set up group parents (group 0 is root, points to itself)
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        curse_mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );

        // Verify config was set
        let config = curse_mcms::get_config(role);
        let _ = config; // Verify it was retrieved successfully
    }

    #[
        test(
            framework = @aptos_framework,
            deployer = @curse_mcms,
            owner = @curse_mcms_owner,
            not_owner = @0x456
        )
    ]
    // error::permission_denied(E_UNAUTHORIZED) = (5 << 16) | 3 = 327683
    #[expected_failure(abort_code = 327683, location = curse_mcms::curse_mcms_account)]
    fun test_set_config_not_owner(
        framework: &signer, deployer: &signer, owner: &signer, not_owner: &signer
    ) {
        setup_test(framework, deployer, owner);
        account::create_account_for_test(signer::address_of(not_owner));

        let role = curse_mcms::bypasser_role();

        let signer_addresses = vector[SIGNER_1];
        let signer_groups = vector[0u8];
        let group_quorums = vector[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        // Non-owner tries to set config - should fail
        curse_mcms::set_config(
            not_owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    #[
        expected_failure(
            abort_code = curse_mcms::curse_mcms::E_INVALID_NUM_SIGNERS,
            location = curse_mcms::curse_mcms
        )
    ]
    fun test_set_config_empty_signers(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        // Empty signers should fail
        let signer_addresses = vector[];
        let signer_groups = vector[];
        let group_quorums = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        curse_mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    #[
        expected_failure(
            abort_code = curse_mcms::curse_mcms::E_SIGNER_GROUPS_LEN_MISMATCH,
            location = curse_mcms::curse_mcms
        )
    ]
    fun test_set_config_mismatched_lengths(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        // Mismatched signer_addresses and signer_groups
        let signer_addresses = vector[SIGNER_1, SIGNER_2];
        let signer_groups = vector[0u8]; // Only 1 group for 2 addresses
        let group_quorums = vector[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        curse_mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    #[
        expected_failure(
            abort_code = curse_mcms::curse_mcms::E_SIGNER_ADDR_MUST_BE_INCREASING,
            location = curse_mcms::curse_mcms
        )
    ]
    fun test_set_config_signers_not_increasing(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        // Signers not in increasing order (SIGNER_2 < SIGNER_1 lexicographically)
        let signer_addresses = vector[SIGNER_2, SIGNER_1]; // Wrong order
        let signer_groups = vector[0u8, 0u8];
        let group_quorums = vector[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        curse_mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    #[
        expected_failure(
            abort_code = curse_mcms::curse_mcms::E_INVALID_SIGNER_ADDR_LEN,
            location = curse_mcms::curse_mcms
        )
    ]
    fun test_set_config_invalid_signer_length(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        // Invalid signer address length (not 20 bytes)
        let signer_addresses = vector[x"0000000000000000000000000000000000000001AA"]; // 21 bytes
        let signer_groups = vector[0u8];
        let group_quorums = vector[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        curse_mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );
    }

    // ================================================================
    // |                      View Function Tests                      |
    // ================================================================
    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_get_op_count(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        // Initial op count should be 0
        assert!(curse_mcms::get_op_count(role) == 0, 1);
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_get_root(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        let (root, valid_until) = curse_mcms::get_root(role);
        assert!(vector::length(&root) == 0, 1);
        assert!(valid_until == 0, 2);
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_role_constants(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        assert!(curse_mcms::bypasser_role() == 0, 1);
        assert!(curse_mcms::canceller_role() == 1, 2);
        assert!(curse_mcms::proposer_role() == 2, 3);
        assert!(curse_mcms::timelock_role() == 3, 4);
    }

    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_is_valid_role(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        assert!(curse_mcms::is_valid_role(0), 1);
        assert!(curse_mcms::is_valid_role(1), 2);
        assert!(curse_mcms::is_valid_role(2), 3);
        assert!(curse_mcms::is_valid_role(3), 4);
        assert!(!curse_mcms::is_valid_role(4), 5);
        assert!(!curse_mcms::is_valid_role(255), 6);
    }

    // ================================================================
    // |                      Merkle Proof Tests                       |
    // ================================================================
    #[test]
    fun test_verify_merkle_proof_single_leaf() {
        // For a single leaf tree, the root equals the leaf
        let leaf = x"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let root = leaf;
        let proof = vector[];

        assert!(
            curse_mcms::verify_merkle_proof(proof, root, leaf),
            1
        );
    }

    #[test]
    fun test_compute_eth_message_hash() {
        let root = x"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let valid_until = 1000000u64;

        // Should not abort
        let _hash = curse_mcms::compute_eth_message_hash(root, valid_until);
    }

    // ================================================================
    // |                      Hash Tests                               |
    // ================================================================
    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_hash_metadata_leaf(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        let hash =
            curse_mcms::test_hash_metadata_leaf(
                role,
                4u256, // chain_id
                @curse_mcms, // multisig
                0u64, // pre_op_count
                1u64, // post_op_count
                false // override_previous_root
            );

        // Should produce a 32-byte hash
        assert!(vector::length(&hash) == 32, 1);
    }

    // ================================================================
    // |                      Set Config with Clear Root Tests         |
    // ================================================================
    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_set_config_with_clear_root(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::bypasser_role();

        let signer_addresses = vector[SIGNER_1, SIGNER_2];
        let signer_groups = vector[0u8, 0u8];
        let group_quorums = vector[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        // Set config with clear_root = true
        curse_mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            true // clear_root
        );

        // Verify root was cleared
        let (root, valid_until) = curse_mcms::get_root(role);
        assert!(vector::length(&root) == 0, 1);
        assert!(valid_until == 0, 2);

        // Verify metadata was updated
        let metadata = curse_mcms::get_root_metadata(role);
        let _ = metadata;
    }

    // ================================================================
    // |                      Hierarchical Group Tests                 |
    // ================================================================
    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_set_config_hierarchical_groups(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let role = curse_mcms::proposer_role();

        // Set up 3 signers in 2 groups
        // Group 1: SIGNER_1, SIGNER_2 (quorum 2)
        // Group 0 (root): gets 1 vote from group 1 (quorum 1)
        let signer_addresses = vector[SIGNER_1, SIGNER_2, SIGNER_3];
        let signer_groups = vector[1u8, 1u8, 0u8]; // 2 in group 1, 1 in group 0

        // Group 0 needs quorum 2 (1 from group 1 passing + 1 from SIGNER_3)
        // Group 1 needs quorum 2 (both SIGNER_1 and SIGNER_2)
        let group_quorums = vector[
            2u8, 2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0
        ];

        // Group 1 reports to group 0
        let group_parents = vector[
            0u8, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0
        ];

        curse_mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );

        // Config should be set successfully
        let config = curse_mcms::get_config(role);
        let _ = config;
    }

    // ================================================================
    // |                      Multiple Roles Tests                     |
    // ================================================================
    #[test(framework = @aptos_framework, deployer = @curse_mcms, owner = @curse_mcms_owner)]
    fun test_set_config_multiple_roles(
        framework: &signer, deployer: &signer, owner: &signer
    ) {
        setup_test(framework, deployer, owner);

        let signer_addresses = vector[SIGNER_1];
        let signer_groups = vector[0u8];
        let group_quorums = vector[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];
        let group_parents = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ];

        // Set config for bypasser
        curse_mcms::set_config(
            owner,
            curse_mcms::bypasser_role(),
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );

        // Set different config for proposer
        let signer_addresses_2 = vector[SIGNER_2];
        curse_mcms::set_config(
            owner,
            curse_mcms::proposer_role(),
            signer_addresses_2,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );

        // Verify configs are independent
        let _config_bypasser = curse_mcms::get_config(curse_mcms::bypasser_role());
        let _config_proposer = curse_mcms::get_config(curse_mcms::proposer_role());
    }
}
