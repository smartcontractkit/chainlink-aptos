#[test_only]
module ccip::nonce_manager_test {
    use std::string;
    use std::account;
    use std::object;

    use ccip::auth;
    use ccip::nonce_manager;
    use ccip::state_object;

    inline fun setup(ccip: &signer, owner: &signer) {
        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);
        nonce_manager::test_init_module(ccip);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_type_and_version(ccip: &signer, owner: &signer) {
        setup(ccip, owner);
        let expected = string::utf8(b"NonceManager 1.6.0");
        let actual = nonce_manager::type_and_version();
        assert!(actual == expected);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_outbound_nonce_uninitialized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);
        // Test getting nonce before any initialization - should return 0
        let nonce = nonce_manager::get_outbound_nonce(1, @0x1);
        assert!(nonce == 0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_outbound_nonce_nonexistent_chain(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Test getting nonce for a chain that doesn't exist - should return 0
        let nonce = nonce_manager::get_outbound_nonce(999, @0x1);
        assert!(nonce == 0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_outbound_nonce_nonexistent_sender(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Test getting nonce for a sender that doesn't exist - should return 0
        let nonce = nonce_manager::get_outbound_nonce(1, @0x999);
        assert!(nonce == 0);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_incremented_outbound_nonce_new_chain_and_sender(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Create an onramp signer and add it to allowlist
        let onramp_address = @0x123;
        let onramp = &account::create_signer_for_test(onramp_address);

        // Add onramp to allowed list
        let allowed_onramps = vector[onramp_address];
        let removed_onramps = vector[];
        auth::apply_allowed_onramp_updates(ccip, removed_onramps, allowed_onramps);

        // Test incrementing nonce for new chain and sender - should return 1
        let dest_chain = 1;
        let sender = @0x456;
        let nonce =
            nonce_manager::get_incremented_outbound_nonce(onramp, dest_chain, sender);
        assert!(nonce == 1);

        // Verify the nonce was stored correctly
        let stored_nonce = nonce_manager::get_outbound_nonce(dest_chain, sender);
        assert!(stored_nonce == 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_get_incremented_outbound_nonce_existing_sender(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Create an onramp signer and add it to allowlist
        let onramp_address = @0x123;
        let onramp = &account::create_signer_for_test(onramp_address);

        // Add onramp to allowed list
        let allowed_onramps = vector[onramp_address];
        let removed_onramps = vector[];
        auth::apply_allowed_onramp_updates(ccip, removed_onramps, allowed_onramps);

        let dest_chain = 1;
        let sender = @0x456;

        // First increment - should return 1
        let nonce1 =
            nonce_manager::get_incremented_outbound_nonce(onramp, dest_chain, sender);
        assert!(nonce1 == 1);

        // Second increment - should return 2
        let nonce2 =
            nonce_manager::get_incremented_outbound_nonce(onramp, dest_chain, sender);
        assert!(nonce2 == 2);

        // Third increment - should return 3
        let nonce3 =
            nonce_manager::get_incremented_outbound_nonce(onramp, dest_chain, sender);
        assert!(nonce3 == 3);

        // Verify the final stored nonce
        let stored_nonce = nonce_manager::get_outbound_nonce(dest_chain, sender);
        assert!(stored_nonce == 3);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_multiple_chains_and_senders(ccip: &signer, owner: &signer) {
        setup(ccip, owner);

        // Create an onramp signer and add it to allowlist
        let onramp_address = @0x123;
        let onramp = &account::create_signer_for_test(onramp_address);

        // Add onramp to allowed list
        let allowed_onramps = vector[onramp_address];
        let removed_onramps = vector[];
        auth::apply_allowed_onramp_updates(ccip, removed_onramps, allowed_onramps);

        let chain1 = 1;
        let chain2 = 2;
        let sender1 = @0x456;
        let sender2 = @0x789;

        // Increment nonces for different combinations
        let nonce_c1_s1_1 =
            nonce_manager::get_incremented_outbound_nonce(onramp, chain1, sender1);
        assert!(nonce_c1_s1_1 == 1);

        let nonce_c1_s2_1 =
            nonce_manager::get_incremented_outbound_nonce(onramp, chain1, sender2);
        assert!(nonce_c1_s2_1 == 1);

        let nonce_c2_s1_1 =
            nonce_manager::get_incremented_outbound_nonce(onramp, chain2, sender1);
        assert!(nonce_c2_s1_1 == 1);

        let nonce_c1_s1_2 =
            nonce_manager::get_incremented_outbound_nonce(onramp, chain1, sender1);
        assert!(nonce_c1_s1_2 == 2);

        // Verify all stored nonces are correct
        assert!(nonce_manager::get_outbound_nonce(chain1, sender1) == 2);
        assert!(nonce_manager::get_outbound_nonce(chain1, sender2) == 1);
        assert!(nonce_manager::get_outbound_nonce(chain2, sender1) == 1);
        assert!(nonce_manager::get_outbound_nonce(chain2, sender2) == 0); // Never incremented
    }

    #[test(ccip = @ccip, owner = @mcms)]
    #[expected_failure(abort_code = 327682, location = ccip::auth)]
    fun test_get_incremented_outbound_nonce_unauthorized(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Create an unauthorized signer (not in onramp allowlist)
        let unauthorized = &account::create_signer_for_test(@0x999);

        // This should fail with unauthorized error
        nonce_manager::get_incremented_outbound_nonce(unauthorized, 1, @0x456);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_nonce_isolation_between_chains(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Create an onramp signer and add it to allowlist
        let onramp_address = @0x123;
        let onramp = &account::create_signer_for_test(onramp_address);

        // Add onramp to allowed list
        let allowed_onramps = vector[onramp_address];
        let removed_onramps = vector[];
        auth::apply_allowed_onramp_updates(ccip, removed_onramps, allowed_onramps);

        let chain1 = 100;
        let chain2 = 200;
        let sender = @0x456;

        // Increment nonce multiple times for chain1
        nonce_manager::get_incremented_outbound_nonce(onramp, chain1, sender);
        nonce_manager::get_incremented_outbound_nonce(onramp, chain1, sender);
        nonce_manager::get_incremented_outbound_nonce(onramp, chain1, sender);

        // Increment nonce once for chain2
        nonce_manager::get_incremented_outbound_nonce(onramp, chain2, sender);

        // Verify nonces are isolated per chain
        assert!(nonce_manager::get_outbound_nonce(chain1, sender) == 3);
        assert!(nonce_manager::get_outbound_nonce(chain2, sender) == 1);
    }

    #[test(ccip = @ccip, owner = @mcms)]
    fun test_nonce_isolation_between_senders(
        ccip: &signer, owner: &signer
    ) {
        setup(ccip, owner);

        // Create an onramp signer and add it to allowlist
        let onramp_address = @0x123;
        let onramp = &account::create_signer_for_test(onramp_address);

        // Add onramp to allowed list
        let allowed_onramps = vector[onramp_address];
        let removed_onramps = vector[];
        auth::apply_allowed_onramp_updates(ccip, removed_onramps, allowed_onramps);

        let chain = 1;
        let sender1 = @0x456;
        let sender2 = @0x789;

        // Increment nonce multiple times for sender1
        nonce_manager::get_incremented_outbound_nonce(onramp, chain, sender1);
        nonce_manager::get_incremented_outbound_nonce(onramp, chain, sender1);
        nonce_manager::get_incremented_outbound_nonce(onramp, chain, sender1);
        nonce_manager::get_incremented_outbound_nonce(onramp, chain, sender1);

        // Increment nonce twice for sender2
        nonce_manager::get_incremented_outbound_nonce(onramp, chain, sender2);
        nonce_manager::get_incremented_outbound_nonce(onramp, chain, sender2);

        // Verify nonces are isolated per sender
        assert!(nonce_manager::get_outbound_nonce(chain, sender1) == 4);
        assert!(nonce_manager::get_outbound_nonce(chain, sender2) == 2);
    }
}
