#[test_only]
module ccip_onramp::onramp_migration_test {
    use std::signer;
    use std::account;
    use std::object;
    use std::object::{Object, ObjectCore};
    use std::fungible_asset::{Metadata};
    use std::timestamp;
    use ccip::state_object;
    use ccip::auth;
    use ccip::rmn_remote;
    use ccip::token_admin_registry;
    use ccip::nonce_manager;
    use ccip::fee_quoter;
    use ccip_onramp::onramp::{Self};
    use ccip_onramp::onramp_test;

    const BURN_MINT_TOKEN_POOL: u8 = 0;
    const LOCK_RELEASE_TOKEN_POOL: u8 = 1;

    const SOURCE_CHAIN_SELECTOR: u64 = 1;
    const DEST_CHAIN_SELECTOR: u64 = 5678;
    const CHAIN_SELECTOR_2: u64 = 743186221051783445;
    const CHAIN_SELECTOR_3: u64 = 421614986313391145;
    const FEE_AGGREGATOR: address = @0x300;
    const ALLOWLIST_ADMIN: address = @0x400;
    const ROUTER: address = @0x200;

    fun init_onramp_for_test(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer
    ): address {
        setup(
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

        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address, router_address]
        );

        // Assert everything got migrated
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));

        // Test V2 function for migrated chains
        let (
            seq1_v2, enabled1_v2, router1_v2, router_state1_v2
        ) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1_v2 == 0);
        assert!(enabled1_v2 == true);
        assert!(router1_v2 == router_address);
        assert!(router_state1_v2 == router_address);
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
        let router_address_2 = @0xdef;
        let router_address_3 = @0x789;

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address_2, router_address_3],
            vector[true, true, true]
        );

        // Verify initial state - chains should be in V1 storage
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        let (seq1, enabled1, router1) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);

        // Migrate specific chains
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address_2, router_address_3]
        );

        // Verify data is now in V2 storage
        let (
            seq1_v2, enabled1_v2, router1_v2, router_state1_v2
        ) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1_v2 == seq1);
        assert!(enabled1_v2 == enabled1);
        assert!(router1_v2 == router1);
        assert!(router_state1_v2 == router_address);
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
    fun test_multiple_migration_calls_allowed(
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
        let router_address_2 = @0xdef;
        let router_address_3 = @0x789;

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address_2, router_address_3],
            vector[true, true, true]
        );

        // Verify 3 more events were emitted (1 + 4)
        assert!(onramp::get_dest_chain_config_set_events().length() == 4);

        // First migration - migrate all chains
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2],
            vector[router_address, router_address_2]
        );

        // Verify events were emitted for all 3 migrated chains (1 + 3 + 2)
        assert!(onramp::get_dest_chain_config_set_events().length() == 6);

        // Verify 2 events emitted for DestChainConfigSetV2 after migration
        assert!(onramp::get_dest_chain_config_v2_set_events().length() == 2);

        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(!onramp::is_chain_supported(CHAIN_SELECTOR_3));

        let (_, _, _, _) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);

        // Second migration call should succeed (no longer blocks multiple calls)
        onramp::migrate_dest_chain_configs_to_v2(
            owner, vector[CHAIN_SELECTOR_3], vector[router_address_3]
        );

        // Verify all chains are still supported after second migration
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));
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
        let router_address_2 = @0xdef;
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2],
            vector[router_address, router_address_2],
            vector[true, true]
        );

        // Initialize will migrate all V1 configs to V2
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2],
            vector[router_address, router_address_2]
        );

        // Verify V2 configs work
        let (
            seq1, enabled1, router1, router_state1
        ) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1 == 0);
        assert!(enabled1 == true);
        assert!(router1 == router_address);
        assert!(router_state1 == router_address);

        let (
            seq2, enabled2, router2, router_state2
        ) = onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        assert!(seq2 == 0);
        assert!(enabled2 == true);
        assert!(router2 == router_address_2);
        assert!(router_state2 == router_address_2);
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
        let router_address_2 = @0xdef;
        let router_address_3 = @0x789;

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address_2, router_address_3],
            vector[true, true, true]
        );

        // Test allowlist functions before migration
        let (enabled1, senders1) = onramp::get_allowed_senders_list(DEST_CHAIN_SELECTOR);
        assert!(enabled1 == true);
        assert!(senders1.is_empty()); // Initially empty

        // Migrate
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address_2, router_address_3]
        );
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
        let router_address = @0xabc;
        onramp::migrate_dest_chain_configs_to_v2(
            aptos_framework,
            vector[DEST_CHAIN_SELECTOR],
            vector[router_address]
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

        let router_address = @0xabc;

        // Simulate sequence number increments by calling config updates
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR],
            vector[router_address],
            vector[true]
        );

        let (original_seq, _, _) = onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);

        // Migrate
        onramp::migrate_dest_chain_configs_to_v2(
            owner, vector[DEST_CHAIN_SELECTOR], vector[router_address]
        );
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
    fun test_migrate_dest_chain_configs_to_v2_auto_migration(
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
        let router_address_2 = @0xdef;
        let router_address_3 = @0x789;

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address_2, router_address_3],
            vector[true, false, true]
        );

        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));
        assert!(!onramp::dest_chain_configs_v2_exists());

        // Auto-migrate ALL V1 configs
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2, CHAIN_SELECTOR_3],
            vector[router_address, router_address_2, router_address_3]
        );

        // Verify V2 exists and all configs were migrated
        assert!(onramp::dest_chain_configs_v2_exists());

        // All chains should still be supported (migrated to V2)
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_3));

        // Verify all V2 configs have correct data
        let (
            seq1, enabled1, router1, router_state1
        ) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq1 == 0);
        assert!(enabled1 == true);
        assert!(router1 == router_address);
        assert!(router_state1 == router_address);

        let (
            seq2, enabled2, router2, router_state2
        ) = onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        assert!(seq2 == 0);
        assert!(enabled2 == false); // Different from chain 1
        assert!(router2 == router_address_2); // Different router
        assert!(router_state2 == router_address_2);

        let (
            seq3, enabled3, router3, router_state3
        ) = onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_3);
        assert!(seq3 == 0);
        assert!(enabled3 == true);
        assert!(router3 == router_address_3); // Different router
        assert!(router_state3 == router_address_3);
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
    fun test_v1_function_works_with_v2_migration(
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
        let router_address_2 = @0xdef;

        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR],
            vector[router_address],
            vector[true]
        );

        // Migrate to V2
        onramp::migrate_dest_chain_configs_to_v2(
            owner, vector[DEST_CHAIN_SELECTOR], vector[router_address]
        );
        assert!(onramp::dest_chain_configs_v2_exists());

        // Now V1 function should work via smart compatibility - routes to V2 function
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[CHAIN_SELECTOR_2],
            vector[router_address_2],
            vector[false]
        );

        // Verify the new chain config was added via V2
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));
        let (seq, enabled, router, router_state) =
            onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        assert!(seq == 0);
        assert!(enabled == false);
        assert!(router == router_address_2);
        assert!(router_state == router_address_2); // Smart compatibility uses same address
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
        let router_address_2 = @0xdef;

        // Set up V1 configuration
        onramp::apply_dest_chain_config_updates(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2],
            vector[router_address, router_address_2],
            vector[true, false]
        );

        // Test V1 function before migration
        let (seq1_v1, enabled1_v1, router1_v1) =
            onramp::get_dest_chain_config(DEST_CHAIN_SELECTOR);
        let (seq2_v1, enabled2_v1, router2_v1) =
            onramp::get_dest_chain_config(CHAIN_SELECTOR_2);

        // Migrate to V2
        onramp::migrate_dest_chain_configs_to_v2(
            owner,
            vector[DEST_CHAIN_SELECTOR, CHAIN_SELECTOR_2],
            vector[router_address, router_address_2]
        );
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
        let (
            seq1_v2, enabled1_v2, router1_v2, router_state1_v2
        ) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);

        // V2 should have same V1-compatible fields plus router_state_address
        assert!(seq1_v2 == seq1_after);
        assert!(enabled1_v2 == enabled1_after);
        assert!(router1_v2 == router1_after);
        assert!(router_state1_v2 == router_address); // Additional V2 field
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
        let router_address = @0xabc;
        onramp::migrate_dest_chain_configs_to_v2(
            owner, vector[DEST_CHAIN_SELECTOR], vector[router_address]
        );
        assert!(onramp::dest_chain_configs_v2_exists());

        // The existing chain should still be supported (now in V2)
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));

        // Verify the V2 config has the migrated data
        let (
            seq, enabled, _router, router_state
        ) = onramp::get_dest_chain_config_v2(DEST_CHAIN_SELECTOR);
        assert!(seq == 0);
        assert!(enabled == false); // From the setup default
        assert!(router_state == @0x200); // ROUTER from setup

        // Should be able to add new V2 configurations for other chains
        onramp::apply_dest_chain_config_updates_v2(
            owner,
            vector[CHAIN_SELECTOR_2],
            vector[router_address],
            vector[onramp::get_state_address()],
            vector[true]
        );

        // Now both chains should be supported
        assert!(onramp::is_chain_supported(DEST_CHAIN_SELECTOR));
        assert!(onramp::is_chain_supported(CHAIN_SELECTOR_2));

        let (
            seq2, enabled2, router2, router_state2
        ) = onramp::get_dest_chain_config_v2(CHAIN_SELECTOR_2);
        assert!(seq2 == 0);
        assert!(enabled2 == true);
        assert!(router2 == @0xabc);
        assert!(router_state2 == onramp::get_state_address()); // V2 config created directly
    }

    fun setup(
        aptos_framework: &signer,
        ccip: &signer,
        ccip_onramp: &signer,
        owner: &signer,
        burn_mint_token_pool: &signer,
        lock_release_token_pool: &signer,
        pool_type: u8, // 0 for burn_mint, 1 for lock_release
        seed: vector<u8>,
        is_dispatchable: bool
    ): (address, Object<Metadata>) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(100000);

        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(signer::address_of(burn_mint_token_pool));
        account::create_account_for_test(signer::address_of(lock_release_token_pool));

        // Create object for @ccip_onramp
        let _constructor_ref = object::create_named_object(owner, b"ccip_onramp");

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        // Create object for @burn_mint_token_pool
        let constructor_ref = object::create_named_object(
            owner, b"burn_mint_token_pool"
        );
        let burn_mint_token_pool_obj_signer = &object::generate_signer(&constructor_ref);

        // Create object for @lock_release_token_pool
        let constructor_ref =
            object::create_named_object(owner, b"lock_release_token_pool");
        let lock_release_token_pool_obj_signer =
            &object::generate_signer(&constructor_ref);

        // Create object for @ccip_token_pool
        let constructor_ref =
            object::create_named_object(
                burn_mint_token_pool_obj_signer, b"ccip_token_pool"
            );
        let ccip_token_pool_obj =
            object::object_from_constructor_ref<ObjectCore>(&constructor_ref);
        // We need to transfer ownership of ccip_token_pool to lock_release_token_pool
        if (pool_type == LOCK_RELEASE_TOKEN_POOL) {
            // transfer ownership of ccip_token_pool to lock_release_token_pool
            object::transfer(
                burn_mint_token_pool_obj_signer,
                ccip_token_pool_obj,
                signer::address_of(lock_release_token_pool_obj_signer)
            );
        };

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);
        rmn_remote::initialize(owner, SOURCE_CHAIN_SELECTOR);

        token_admin_registry::init_module_for_testing(ccip);
        onramp::test_init_module(ccip_onramp);
        nonce_manager::test_init_module(ccip_onramp);

        let (token_obj, token_addr) =
            onramp_test::create_test_token_and_pool(
                owner,
                burn_mint_token_pool,
                lock_release_token_pool,
                pool_type,
                seed,
                is_dispatchable,
                false // use_v1_init
            );

        let one_e_18 = 1_000_000_000_000_000_000;

        fee_quoter::initialize(
            owner,
            200 * one_e_18, // 200 link
            token_addr,
            12400,
            vector[token_addr]
        );

        onramp::initialize_v1(
            owner,
            SOURCE_CHAIN_SELECTOR,
            FEE_AGGREGATOR,
            ALLOWLIST_ADMIN,
            vector[DEST_CHAIN_SELECTOR],
            vector[ROUTER],
            vector[false]
        );

        (owner_addr, token_obj)
    }
}
