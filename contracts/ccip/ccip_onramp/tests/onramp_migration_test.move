#[test_only]
module ccip_onramp::onramp_migration_test {
    use ccip_onramp::onramp::{Self};
    use ccip_onramp::onramp_test;

    const BURN_MINT_TOKEN_POOL: u8 = 0;
    const LOCK_RELEASE_TOKEN_POOL: u8 = 1;

    const DEST_CHAIN_SELECTOR: u64 = 5678;
    const CHAIN_SELECTOR_2: u64 = 743186221051783445;
    const CHAIN_SELECTOR_3: u64 = 421614986313391145;

    fun init_onramp_for_test(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ): address {
        onramp_test::setup(
            aptos_framework,
            ccip,
            ccip_onramp,
            owner,
            burn_mint_token_pool,
            lock_release_token_pool,
            BURN_MINT_TOKEN_POOL,
            b"TestToken",
            false
        );

        onramp::get_state_address()
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_migration_functionality_preservation(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        let router_address = @0xabc;

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address, router_address],
            vector[true, true, true]
        );

        // Test that V1 functions work before migration
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));
        assert!(!onramp::is_chain_supported(999));

        let (seq1, enabled1, router1) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        assert!(seq1 == 0);
        assert!(enabled1 == true);
        assert!(router1 == router_address);

        let next_seq = onramp::get_expected_next_sequence_number(DEST_CHAIN_SELECTOR);
        assert!(next_seq == 1);

        // Migrate first two chains
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2]
        );

        // Test that functions still work after partial migration
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(!onramp::is_chain_supported(CHAIN_SELECTOR_3)); // Still in V1

        // Test V2 function for migrated chains
        let (seq1_v2, enabled1_v2, router1_v2, router_state1_v2) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1_v2 == 0);
        assert!(enabled1_v2 == true);
        assert!(router1_v2 == router_address);
        assert!(router_state1_v2 == onramp::get_state_address());
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_migration_data_movement(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        let router_address = @0xabc;
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address, router_address],
            vector[true, true, true]
        );

        // Verify initial state - chains should be in V1 storage
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        let (seq1, enabled1, router1) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);

        // Migrate specific chains
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2]
        );

        // Verify data is now in V2 storage
        let (seq1_v2, enabled1_v2, router1_v2, router_state1_v2) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1_v2 == seq1);
        assert!(enabled1_v2 == enabled1);
        assert!(router1_v2 == router1);
        assert!(router_state1_v2 == state_address);

        // Chain 3 was NOT migrated, so it won't exist in V2 storage
        // The system now uses V2 resource, so chain 3 should not be supported
        assert!(!onramp::is_chain_supported(CHAIN_SELECTOR_3));
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_incremental_migration(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        let router_address = @0xabc;
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address, router_address],
            vector[true, true, true]
        );

        // First migration batch - migrate only DEST_CHAIN_SELECTOR
        onramp::migrate_dest_chain_configs_to_v2(owner, vector[DEST_CHAIN_SELECTOR]);

        // After creating V2 storage, system switches to V2 for all operations
        // Only migrated chains will be supported
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        let (_, _, _, _) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);

        // Chain 2 and 3 were NOT migrated, so they won't exist in V2 storage
        assert!(!onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(!onramp::is_chain_supported(CHAIN_SELECTOR_3));

        // Second migration batch
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[CHAIN_SELECTOR_2, CHAIN_SELECTOR_3]
        );

        // Verify all chains are now in V2
        let (_, _, _, _) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        let (_, _, _, _) = onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        let (_, _, _, _) = onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_3);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_v2_initialization_functionality(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        // Test direct V2 initialization (without migration)
        onramp::initialize_dest_chain_configs_v2(
            owner,
            vector[12345, 67890],
            vector[@0x999, @0x888],
            vector[@0x777, @0x666],
            vector[false, true]
        );

        // Verify V2 configs work
        let (seq1, enabled1, router1, router_state1) =
            onramp::get_dest_chain_config_v2(12345);
        assert!(seq1 == 0);
        assert!(enabled1 == false);
        assert!(router1 == @0x999);
        assert!(router_state1 == @0x777);

        let (seq2, enabled2, router2, router_state2) =
            onramp::get_dest_chain_config_v2(67890);
        assert!(seq2 == 0);
        assert!(enabled2 == true);
        assert!(router2 == @0x888);
        assert!(router_state2 == @0x666);
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_allowlist_functions_after_migration(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        let router_address = @0xabc;
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address, router_address],
            vector[true, true, true]
        );

        // Test allowlist functions before migration
        let (enabled1, senders1) = onramp::get_allowed_senders_list(DEST_CHAIN_SELECTOR);
        assert!(enabled1 == true);
        assert!(senders1.is_empty()); // Initially empty

        // Migrate
        onramp::migrate_dest_chain_configs_to_v2(owner, vector[DEST_CHAIN_SELECTOR]);
        assert!(onramp::dest_chain_configs_v2_exists());

        // Test allowlist functions after migration
        let (enabled1_v2, senders1_v2) =
            onramp::get_allowed_senders_list(DEST_CHAIN_SELECTOR);
        assert!(enabled1_v2 == enabled1);
        assert!(senders1_v2.length() == senders1.length());

        // Test allowlist updates work on migrated chains
        onramp::apply_allowlist_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR],
            vector[true],
            vector[vector[@0x123, @0x456]],
            vector[vector[]]
        );

        let (enabled1_updated, senders1_updated) =
            onramp::get_allowed_senders_list(DEST_CHAIN_SELECTOR);
        assert!(enabled1_updated == true);
        assert!(senders1_updated.length() == 2);
        assert!(senders1_updated.contains(&@0x123));
        assert!(senders1_updated.contains(&@0x456));
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    #[expected_failure(abort_code = 196631, location = ccip_onramp::onramp)]
    fun test_double_v2_initialization_fails(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        // First initialization should succeed
        onramp::initialize_dest_chain_configs_v2(
            owner,
            vector[12345],
            vector[@0x999],
            vector[@0x777],
            vector[false]
        );

        // Second initialization should fail
        onramp::initialize_dest_chain_configs_v2(
            owner,
            vector[67890],
            vector[@0x888],
            vector[@0x666],
            vector[true]
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    #[expected_failure(abort_code = 65537, location = std::smart_table)]
    // Should fail because chain doesn't exist in V1
    fun test_migration_nonexistent_chain_fails(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        // Try to migrate a chain that doesn't exist
        // Aborts from `smart_table` module when calling `remove`
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[999999] // Non-existent chain
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    // Should fail due to ownership check
    fun test_migration_requires_ownership(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );
        // Non-owner should not be able to migrate
        onramp::migrate_dest_chain_configs_to_v2(
            aptos_framework, vector[DEST_CHAIN_SELECTOR]
        );
    }

    #[
        test(
            aptos_framework = @aptos_framework,
            ccip = @ccip,
            ccip_onramp = @ccip_onramp,
            owner = @0x100,
            burn_mint_token_pool = @burn_mint_token_pool,
            lock_release_token_pool = @lock_release_token_pool
        )
    ]
    fun test_sequence_number_preservation(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ) {
        let _state_address =
            init_onramp_for_test(
                aptos_framework,
                ccip,
                ccip_onramp,
                owner,
                burn_mint_token_pool,
                lock_release_token_pool
            );

        // Simulate sequence number increments by calling config updates
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR],
            vector[@0xabc],
            vector[true]
        );

        let (original_seq, _, _) = onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);

        // Migrate
        onramp::migrate_dest_chain_configs_to_v2(owner, vector[DEST_CHAIN_SELECTOR]);
        assert!(onramp::dest_chain_configs_v2_exists());

        // Verify sequence number is preserved
        let (migrated_seq, _, _, _) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(migrated_seq == original_seq);
    }
}
