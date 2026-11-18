#[test_only]
module forwarder_mcms_adapter::adapter_test {
    use std::account;
    use std::bcs;
    use std::signer;
    use std::object::{Self, ObjectCore};
    use std::string;

    use mcms::mcms_account;
    use mcms::mcms_registry;

    use platform::forwarder as primary;
    use platform_secondary::forwarder as secondary;

    use forwarder_mcms_adapter::adapter;

    const NEW_OWNER: address = @0xbeef;

    // ================================================================
    // |                          Helpers                             |
    // ================================================================

    fun setup(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        account::create_account_for_test(signer::address_of(mcms));
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        primary::init_module_for_testing(fwd);
        secondary::init_module_for_testing(fwd2);
        adapter::test_init_module(adapter_signer);
    }

    /// Simulates MCMS executing one op against the adapter.
    fun dispatch(function: vector<u8>, data: vector<u8>) {
        let metadata =
            mcms_registry::test_start_dispatch(
                @forwarder_mcms_adapter,
                adapter::module_name(),
                string::utf8(function),
                data
            );
        adapter::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@forwarder_mcms_adapter);
    }

    /// Current owners propose the adapter's MCMS owner account; MCMS accepts both via the adapter.
    fun hand_both_to_mcms(owner: &signer, owner2: &signer) {
        let mcms_owner = adapter::mcms_owner_address();
        primary::transfer_ownership(owner, mcms_owner);
        secondary::transfer_ownership(owner2, mcms_owner);
        dispatch(b"accept_ownership", bcs::to_bytes(&@platform));
        dispatch(b"accept_ownership", bcs::to_bytes(&@platform_secondary));
    }

    /// 32-byte dummy ed25519 public key (set_config stores keys unvalidated).
    fun key(b: u8): vector<u8> {
        let k = vector[];
        for (_i in 0..32) {
            k.push_back(b);
        };
        k
    }

    /// 3f+1 = 4 oracles for f = 1.
    fun oracles(seed: u8): vector<vector<u8>> {
        vector[key(seed), key(seed + 1), key(seed + 2), key(seed + 3)]
    }

    fun set_config_args(
        target: address,
        don_id: u32,
        config_version: u32,
        f: u8,
        oracles: vector<vector<u8>>
    ): vector<u8> {
        let data = bcs::to_bytes(&target);
        data.append(bcs::to_bytes(&don_id));
        data.append(bcs::to_bytes(&config_version));
        data.append(bcs::to_bytes(&f));
        data.append(bcs::to_bytes(&oracles));
        data
    }

    fun clear_config_args(
        target: address, don_id: u32, config_version: u32
    ): vector<u8> {
        let data = bcs::to_bytes(&target);
        data.append(bcs::to_bytes(&don_id));
        data.append(bcs::to_bytes(&config_version));
        data
    }

    fun transfer_ownership_args(target: address, to: address): vector<u8> {
        let data = bcs::to_bytes(&target);
        data.append(bcs::to_bytes(&to));
        data
    }

    // ================================================================
    // |                     Views & registration                     |
    // ================================================================

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary)]
    fun test_views(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);

        let (p, s) = adapter::forwarders();
        assert!(p == @platform, 1);
        assert!(s == @platform_secondary, 2);

        // Registered via init_module; for a package deployed outside mcms_deployer the owner is the
        // pre-existing-object owner account.
        assert!(
            adapter::mcms_owner_address()
                == mcms_registry::get_preexisting_code_object_owner_address(
                    @forwarder_mcms_adapter
                ),
            3
        );
        assert!(
            adapter::type_and_version() == string::utf8(b"ForwarderMcmsAdapter 1.0.0"),
            4
        );
    }

    // ================================================================
    // |                     Ownership handover                       |
    // ================================================================

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    fun test_accept_ownership_both(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        assert!(primary::get_owner() == @owner, 1);
        assert!(secondary::get_owner() == @owner_secondary, 2);

        hand_both_to_mcms(owner, owner2);

        let mcms_owner = adapter::mcms_owner_address();
        assert!(primary::get_owner() == mcms_owner, 3);
        assert!(secondary::get_owner() == mcms_owner, 4);
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    fun test_transfer_ownership_out_of_mcms(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        hand_both_to_mcms(owner, owner2);

        // MCMS hands primary to a new owner; secondary stays with MCMS.
        dispatch(b"transfer_ownership", transfer_ownership_args(@platform, NEW_OWNER));
        primary::accept_ownership(&account::create_signer_for_test(NEW_OWNER));
        assert!(primary::get_owner() == NEW_OWNER, 1);
        assert!(secondary::get_owner() == adapter::mcms_owner_address(), 2);

        // And secondary too.
        dispatch(
            b"transfer_ownership",
            transfer_ownership_args(@platform_secondary, NEW_OWNER)
        );
        secondary::accept_ownership(&account::create_signer_for_test(NEW_OWNER));
        assert!(secondary::get_owner() == NEW_OWNER, 3);
    }

    // ================================================================
    // |                     set_config / clear_config                |
    // ================================================================

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    fun test_set_config_primary(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        // Reference config written directly by the owner, before the handover.
        primary::set_config(owner, 2, 1, 1, oracles(10));
        hand_both_to_mcms(owner, owner2);

        dispatch(b"set_config", set_config_args(@platform, 1, 1, 1, oracles(10)));

        // Same args through the adapter must yield the identical config.
        assert!(primary::get_config(1, 1) == primary::get_config(2, 1), 1);
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    fun test_set_config_secondary(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        secondary::set_config(owner2, 2, 1, 1, oracles(20));
        hand_both_to_mcms(owner, owner2);

        dispatch(
            b"set_config", set_config_args(@platform_secondary, 1, 1, 1, oracles(20))
        );

        assert!(secondary::get_config(1, 1) == secondary::get_config(2, 1), 1);
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    fun test_set_config_max_oracles_and_overwrite(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        // 31 oracles (MAX_ORACLES), f = 10 (3f+1 = 31): largest payload the forwarder accepts.
        let many = vector[];
        for (i in 0..31) {
            many.push_back(key((i as u8) + 100));
        };
        primary::set_config(owner, 2, 1, 10, many);
        hand_both_to_mcms(owner, owner2);

        // First write a different config, then overwrite (set_config upserts).
        dispatch(b"set_config", set_config_args(@platform, 1, 1, 1, oracles(1)));
        assert!(primary::get_config(1, 1) != primary::get_config(2, 1), 1);
        dispatch(b"set_config", set_config_args(@platform, 1, 1, 10, many));
        assert!(primary::get_config(1, 1) == primary::get_config(2, 1), 2);
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    #[expected_failure]
    fun test_clear_config_primary(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        hand_both_to_mcms(owner, owner2);
        dispatch(b"set_config", set_config_args(@platform, 1, 1, 1, oracles(1)));
        primary::get_config(1, 1);
        dispatch(b"clear_config", clear_config_args(@platform, 1, 1));
        // Aborts: config was removed.
        primary::get_config(1, 1);
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    #[expected_failure]
    fun test_clear_config_secondary(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        hand_both_to_mcms(owner, owner2);
        dispatch(
            b"set_config", set_config_args(@platform_secondary, 1, 1, 1, oracles(1))
        );
        secondary::get_config(1, 1);
        dispatch(b"clear_config", clear_config_args(@platform_secondary, 1, 1));
        secondary::get_config(1, 1);
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    #[expected_failure(abort_code = 65545, location = platform::forwarder)]
    fun test_set_config_forwarder_validation_applies(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        hand_both_to_mcms(owner, owner2);
        // E_FAULT_TOLERANCE_MUST_BE_POSITIVE: the forwarder's own checks still run
        dispatch(b"set_config", set_config_args(@platform, 1, 1, 0, oracles(1)));
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary, owner = @owner, owner2 = @owner_secondary)]
    #[expected_failure(abort_code = 65547, location = platform_secondary::forwarder)]
    fun test_set_config_insufficient_signers_secondary(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        hand_both_to_mcms(owner, owner2);
        // E_INSUFFICIENT_SIGNERS: f = 2 needs 7 oracles
        dispatch(
            b"set_config", set_config_args(@platform_secondary, 1, 1, 2, oracles(1))
        );
    }

    // ================================================================
    // |                     Input validation                         |
    // ================================================================

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary)]
    #[expected_failure(abort_code = 65538, location = forwarder_mcms_adapter::adapter)]
    fun test_unknown_forwarder(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        dispatch(b"set_config", set_config_args(@0xbad, 1, 1, 1, oracles(1)));
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary)]
    #[expected_failure(abort_code = 65538, location = forwarder_mcms_adapter::adapter)]
    fun test_unknown_forwarder_adapter_address(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        // The adapter itself is not a valid target.
        dispatch(b"accept_ownership", bcs::to_bytes(&@forwarder_mcms_adapter));
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary)]
    #[expected_failure(abort_code = 65537, location = forwarder_mcms_adapter::adapter)]
    fun test_unknown_function(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        dispatch(b"report", bcs::to_bytes(&@platform));
    }

    // ================================================================
    // |                     No back doors                            |
    // ================================================================

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary)]
    #[expected_failure(abort_code = 327684, location = forwarder_mcms_adapter::adapter)]
    fun test_init_requires_mcms_published_code(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        account::create_account_for_test(signer::address_of(mcms));
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);
        primary::init_module_for_testing(fwd);
        secondary::init_module_for_testing(fwd2);
        // No MCMS-owned code object at the adapter address -> E_NOT_PUBLISHED_BY_MCMS.
        // (Published by an EOA, the code object exists but is not registered with MCMS, and
        // mcms_registry::is_owned_code_object aborts instead. Either way init_module fails.)
        adapter::test_init_module_strict(adapter_signer);
    }

    #[test(mcms = @mcms, adapter_signer = @forwarder_mcms_adapter, fwd = @platform, fwd2 = @platform_secondary)]
    #[expected_failure(abort_code = 65539, location = mcms::mcms_registry)]
    fun test_other_module_cannot_take_signer_during_dispatch(
        mcms: &signer,
        adapter_signer: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter_signer, fwd, fwd2);
        // A genuine MCMS dispatch to the adapter is in progress ...
        mcms_registry::test_start_dispatch(
            @forwarder_mcms_adapter,
            adapter::module_name(),
            string::utf8(b"accept_ownership"),
            bcs::to_bytes(&@platform)
        );
        // ... but any proof other than adapter::McmsCallback (constructible only inside the
        // adapter module) is rejected: E_WRONG_PROOF_TYPE.
        let (_s, _f, _d) =
            mcms_registry::get_callback_params(@forwarder_mcms_adapter, AttackerProof {});
    }

    struct AttackerProof has drop {}
}
