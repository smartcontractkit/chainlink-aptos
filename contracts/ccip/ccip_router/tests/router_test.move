#[test_only]
module ccip::router_tests {
    use std::account;
    use std::signer;
    use std::object;
    use ccip_router::router;

    const ETH_CHAIN_SELECTOR: u64 = 5009297550715157269;
    const AVAX_CHAIN_SELECTOR: u64 = 6433500567565415381;
    const BSC_CHAIN_SELECTOR: u64 = 4380317901350075273;
    const ARBITRARY_CHAIN_SELECTOR: u64 = 123456789;

    const VERSION_1_6_0: vector<u8> = vector[1, 6, 0];
    const INVALID_VERSION: vector<u8> = vector[1, 2]; // Invalid because it has 2 elements, not 3
    fun setup(ccip_router: &signer, owner: &signer) {
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(ccip_router));

        // Create object for @ccip_router
        let _constructor_ref = &object::create_named_object(owner, b"ccip_router");

        router::test_init_module(ccip_router);
    }

    #[test(router = @ccip_router, owner = @0x123)]
    fun test_initialization(router: &signer, owner: &signer) {
        setup(router, owner);

        assert!(router::owner() == signer::address_of(owner));
        assert!(router::type_and_version() == std::string::utf8(b"Router 1.6.0"));
    }

    #[test(router = @ccip_router, owner = @0x123)]
    fun test_set_and_get_on_ramp_versions(
        router: &signer, owner: &signer
    ) {
        setup(router, owner);

        let dest_chain_selectors = vector[ETH_CHAIN_SELECTOR, AVAX_CHAIN_SELECTOR];
        let on_ramp_versions = vector[VERSION_1_6_0, VERSION_1_6_0];

        router::set_on_ramp_versions(owner, dest_chain_selectors, on_ramp_versions);

        // Test get_on_ramp_versions with existing chains
        let versions = router::get_on_ramp_versions(dest_chain_selectors);
        assert!(versions.length() == 2);
        assert!(versions[0] == VERSION_1_6_0);
        assert!(versions[1] == VERSION_1_6_0);

        // Test get_on_ramp_versions with non-existent chain
        let non_existent_chain = vector[BSC_CHAIN_SELECTOR];
        let non_existent_versions = router::get_on_ramp_versions(non_existent_chain);
        assert!(non_existent_versions.length() == 1);
        assert!(non_existent_versions[0].is_empty());

        // Test get_on_ramp_versions with mixed existing and non-existing chains
        let mixed_chains = vector[ETH_CHAIN_SELECTOR, BSC_CHAIN_SELECTOR, AVAX_CHAIN_SELECTOR];
        let mixed_versions = router::get_on_ramp_versions(mixed_chains);
        assert!(mixed_versions.length() == 3);
        assert!(mixed_versions[0] == VERSION_1_6_0); // ETH exists
        assert!(mixed_versions[1].is_empty()); // BSC doesn't exist
        assert!(mixed_versions[2] == VERSION_1_6_0); // AVAX exists
    }

    #[test(router = @ccip_router, owner = @0x123)]
    fun test_remove_on_ramp_version(router: &signer, owner: &signer) {
        setup(router, owner);

        // First add some chains
        let dest_chain_selectors = vector[ETH_CHAIN_SELECTOR, AVAX_CHAIN_SELECTOR];
        let on_ramp_versions = vector[VERSION_1_6_0, VERSION_1_6_0];
        router::set_on_ramp_versions(owner, dest_chain_selectors, on_ramp_versions);

        // Verify they were added
        assert!(router::is_chain_supported(ETH_CHAIN_SELECTOR));
        assert!(router::is_chain_supported(AVAX_CHAIN_SELECTOR));

        // Now remove one of them by setting an empty version
        let remove_selectors = vector[ETH_CHAIN_SELECTOR];
        let remove_versions = vector[vector[]]; // Empty version removes the chain
        router::set_on_ramp_versions(owner, remove_selectors, remove_versions);

        // Verify it was removed
        assert!(!router::is_chain_supported(ETH_CHAIN_SELECTOR));
        assert!(router::is_chain_supported(AVAX_CHAIN_SELECTOR)); // This one should still exist

        // Check with get_on_ramp_versions
        let check_selectors = vector[ETH_CHAIN_SELECTOR, AVAX_CHAIN_SELECTOR];
        let versions = router::get_on_ramp_versions(check_selectors);
        assert!(versions[0].is_empty()); // ETH was removed
        assert!(versions[1] == VERSION_1_6_0); // AVAX still exists
    }

    #[test(router = @ccip_router, owner = @0x123)]
    fun test_get_on_ramp(router: &signer, owner: &signer) {
        setup(router, owner);

        // Add a supported chain
        router::set_on_ramp_versions(
            owner, vector[ETH_CHAIN_SELECTOR], vector[VERSION_1_6_0]
        );

        // Test get_on_ramp returns the correct address for v1.6.0
        let onramp_address = router::get_on_ramp(ETH_CHAIN_SELECTOR);
        assert!(onramp_address == @ccip_onramp);
    }

    #[test(router = @ccip_router, owner = @0x123, non_owner = @0x456)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    fun test_set_on_ramp_versions_not_owner(
        router: &signer, owner: &signer, non_owner: &signer
    ) {
        setup(router, owner);

        account::create_account_for_test(signer::address_of(non_owner));

        // This should fail because only the owner can set on ramp versions
        router::set_on_ramp_versions(
            non_owner, vector[ETH_CHAIN_SELECTOR], vector[VERSION_1_6_0]
        );
    }

    #[test(router = @ccip_router, owner = @0x123)]
    #[expected_failure(abort_code = 65540, location = ccip_router::router)]
    fun test_set_invalid_on_ramp_version(router: &signer, owner: &signer) {
        setup(router, owner);

        // Fails with E_INVALID_ON_RAMP_VERSION: the version has 2 elements instead of 3
        router::set_on_ramp_versions(
            owner, vector[ETH_CHAIN_SELECTOR], vector[INVALID_VERSION]
        );
    }

    #[test(router = @ccip_router, owner = @0x123)]
    #[expected_failure(abort_code = 65538, location = ccip_router::router)]
    fun test_get_on_ramp_unsupported_chain(
        router: &signer, owner: &signer
    ) {
        setup(router, owner);

        // This should fail because the chain is not supported
        router::get_on_ramp(ARBITRARY_CHAIN_SELECTOR);
    }
}
