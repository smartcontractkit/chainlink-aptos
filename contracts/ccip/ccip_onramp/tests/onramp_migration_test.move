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

        onramp::migrate_dest_chain_configs_to_v2(owner);

        // Assert everything got migrated
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));

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
        onramp::migrate_dest_chain_configs_to_v2(owner);

        // Verify data is now in V2 storage
        let (seq1_v2, enabled1_v2, router1_v2, router_state1_v2) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1_v2 == seq1);
        assert!(enabled1_v2 == enabled1);
        assert!(router1_v2 == router1);
        assert!(router_state1_v2 == state_address);
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
        // Setup emits 1 DestChainConfigSet event
        assert!(onramp::get_dest_chain_config_set_events().length() == 1);

        let router_address = @0xabc;
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address, router_address],
            vector[true, true, true]
        );

        // Verify 3 more events were emitted (1 + 4)
        assert!(onramp::get_dest_chain_config_set_events().length() == 4);

        // First migration batch - migrate only DEST_CHAIN_SELECTOR
        onramp::migrate_dest_chain_configs_to_v2(owner);

        // Verify 3 more events were emitted (1 + 4)
        assert!(onramp::get_dest_chain_config_set_events().length() == 7);

        // Verify 3 events emitted for DestChainConfigSetV2 after migration
        assert!(onramp::get_dest_chain_config_v2_set_events().length() == 3);

        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));

        let (_, _, _, _) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);

        // Call migrate again, but no new chains were migrated
        onramp::migrate_dest_chain_configs_to_v2(owner);

        // Verify no new events were emitted as we did not migrate any more chains
        assert!(onramp::get_dest_chain_config_set_events().length() == 7);
        assert!(onramp::get_dest_chain_config_v2_set_events().length() == 3);
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

        let router_address = @0xabc;
        let router_state_address = onramp::get_state_address();
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2],
            vector[router_address, router_address],
            vector[true, true]
        );

        // Initialize will migrate all V1 configs to V2
        onramp::initialize_dest_chain_configs_v2(owner);

        // Verify V2 configs work
        let (seq1, enabled1, router1, router_state1) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1 == 0);
        assert!(enabled1 == true);
        assert!(router1 == router_address);
        assert!(router_state1 == router_state_address);

        let (seq2, enabled2, router2, router_state2) =
            onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        assert!(seq2 == 0);
        assert!(enabled2 == true);
        assert!(router2 == router_address);
        assert!(router_state2 == router_state_address);
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
        onramp::migrate_dest_chain_configs_to_v2(owner);
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
        onramp::initialize_dest_chain_configs_v2(owner);

        // Second initialization should fail
        onramp::initialize_dest_chain_configs_v2(owner);
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
        onramp::migrate_dest_chain_configs_to_v2(aptos_framework);
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
        onramp::migrate_dest_chain_configs_to_v2(owner);
        assert!(onramp::dest_chain_configs_v2_exists());

        // Verify sequence number is preserved
        let (migrated_seq, _, _, _) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(migrated_seq == original_seq);
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
    fun test_initialize_dest_chain_configs_v2_auto_migration(
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
            vector[router_address, @0xdef, @0x789],
            vector[true, false, true]
        );

        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));
        assert!(!onramp::dest_chain_configs_v2_exists());

        // Auto-migrate ALL V1 configs
        onramp::initialize_dest_chain_configs_v2(owner);

        // Verify V2 exists and all configs were migrated
        assert!(onramp::dest_chain_configs_v2_exists());

        // All chains should still be supported (migrated to V2)
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));

        // Verify all V2 configs have correct data
        let (seq1, enabled1, router1, router_state1) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1 == 0);
        assert!(enabled1 == true);
        assert!(router1 == router_address);
        assert!(router_state1 == state_address);

        let (seq2, enabled2, router2, router_state2) =
            onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        assert!(seq2 == 0);
        assert!(enabled2 == false); // Different from chain 1
        assert!(router2 == @0xdef); // Different router
        assert!(router_state2 == state_address);

        let (seq3, enabled3, router3, router_state3) =
            onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_3);
        assert!(seq3 == 0);
        assert!(enabled3 == true);
        assert!(router3 == @0x789); // Different router
        assert!(router_state3 == state_address);
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
    fun test_v1_function_reverts_after_v2_migration(
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

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR],
            vector[@0xabc],
            vector[true]
        );

        // Migrate to V2
        onramp::initialize_dest_chain_configs_v2(owner);
        assert!(onramp::dest_chain_configs_v2_exists());

        // Now trying to use V1 function should fail with E_DEST_CHAIN_CONFIGS_V2_ALREADY_INITIALIZED
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[CHAIN_SELECTOR_2],
            vector[@0xdef],
            vector[false]
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
    fun test_backward_compatible_get_dest_chain_config(
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

        // Set up V1 configuration
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2],
            vector[router_address, @0xdef],
            vector[true, false]
        );

        // Test V1 function before migration
        let (seq1_v1, enabled1_v1, router1_v1) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        let (seq2_v1, enabled2_v1, router2_v1) =
            onramp::get_dest_chain_config(CHAIN_SELECTOR_2);

        // Migrate to V2
        onramp::initialize_dest_chain_configs_v2(owner);
        assert!(onramp::dest_chain_configs_v2_exists());

        // Test that V1 function now reads from V2 storage but returns V1-compatible data
        let (seq1_after, enabled1_after, router1_after) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        let (seq2_after, enabled2_after, router2_after) =
            onramp::get_dest_chain_config(CHAIN_SELECTOR_2);

        // Should return the same data as before migration (backward compatibility)
        assert!(seq1_after == seq1_v1);
        assert!(enabled1_after == enabled1_v1);
        assert!(router1_after == router1_v1);

        assert!(seq2_after == seq2_v1);
        assert!(enabled2_after == enabled2_v1);
        assert!(router2_after == router2_v1);

        // Verify V2 function returns additional field
        let (seq1_v2, enabled1_v2, router1_v2, router_state1_v2) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);

        // V2 should have same V1-compatible fields plus router_state_address
        assert!(seq1_v2 == seq1_after);
        assert!(enabled1_v2 == enabled1_after);
        assert!(router1_v2 == router1_after);
        assert!(router_state1_v2 == onramp::get_state_address()); // Additional V2 field
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
    fun test_existing_v1_auto_migration(
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

        // The setup function automatically adds DEST_CHAIN_SELECTOR to V1
        // So this tests auto-migration with pre-existing V1 data
        assert!(!onramp::dest_chain_configs_v2_exists());

        // Verify the chain exists in V1 (from setup)
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));

        // Initialize V2 - should auto-migrate the existing V1 configuration
        onramp::initialize_dest_chain_configs_v2(owner);
        assert!(onramp::dest_chain_configs_v2_exists());

        // The existing chain should still be supported (now in V2)
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));

        // Verify the V2 config has the migrated data
        let (seq, enabled, _router, router_state) =
            onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq == 0);
        assert!(enabled == false); // From the setup default
        assert!(router_state == onramp::get_state_address());

        // Should be able to add new V2 configurations for other chains
        onramp::apply_dest_chain_config_updates_v2(
            owner,
            vector[CHAIN_SELECTOR_2],
            vector[@0xabc],
            vector[onramp::get_state_address()],
            vector[true]
        );

        // Now both chains should be supported
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));

        let (seq2, enabled2, router2, router_state2) =
            onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        assert!(seq2 == 0);
        assert!(enabled2 == true);
        assert!(router2 == @0xabc);
        assert!(router_state2 == onramp::get_state_address());
    }
}
