/// MCMS adapter for both dummy forwarders (dummy_forwarder + dummy_forwarder_secondary),
/// mirroring the prod shape: one adapter, one MCMS entrypoint, one MCMS owner account.
///
/// MCMS reaches this module through the dispatchable FA hook (no compile-time dependency on us),
/// and this module statically calls the forwarders' public entry functions using the signer of
/// the MCMS owner resource account registered for this package. Making that account the owner of
/// both forwarders gives MCMS control of them without changing the forwarder code.
///
/// Every function takes the target forwarder address as its first BCS argument; it must be
/// @dummy_forwarder or @dummy_forwarder_secondary.
module forwarder_mcms_adapter::adapter {
    use std::error;
    use std::object::Object;
    use std::option::{Self, Option};
    use std::string;

    use mcms::bcs_stream::{Self, BCSStream};
    use mcms::mcms_registry;

    use dummy_forwarder::forwarder as primary;
    use dummy_forwarder_secondary::forwarder as secondary;

    const E_UNKNOWN_FUNCTION: u64 = 1;
    const E_UNKNOWN_FORWARDER: u64 = 2;

    struct McmsCallback has drop {}

    fun init_module(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"adapter"), McmsCallback {}
        );
    }

    #[view]
    /// The address MCMS signs as when calling through this adapter. Both forwarders' owner must
    /// be set to this address.
    public fun mcms_owner_address(): address {
        mcms_registry::get_registered_owner_address(@forwarder_mcms_adapter)
    }

    #[view]
    /// The forwarders this adapter can target: (primary, secondary).
    public fun forwarders(): (address, address) {
        (@dummy_forwarder, @dummy_forwarder_secondary)
    }

    public fun mcms_entrypoint<T: key>(_metadata: Object<T>): Option<u128> {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@forwarder_mcms_adapter, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"set_value") {
            let is_primary = deserialize_target(&mut stream);
            let value = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            if (is_primary) {
                primary::set_value(&caller, value)
            } else {
                secondary::set_value(&caller, value)
            }
        } else if (function_bytes == b"transfer_ownership") {
            let is_primary = deserialize_target(&mut stream);
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            if (is_primary) {
                primary::transfer_ownership(&caller, to)
            } else {
                secondary::transfer_ownership(&caller, to)
            }
        } else if (function_bytes == b"accept_ownership") {
            let is_primary = deserialize_target(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            if (is_primary) {
                primary::accept_ownership(&caller)
            } else {
                secondary::accept_ownership(&caller)
            }
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    /// Reads the target forwarder address. Returns true for primary, false for secondary,
    /// aborts for anything else.
    fun deserialize_target(stream: &mut BCSStream): bool {
        let target = bcs_stream::deserialize_address(stream);
        if (target == @dummy_forwarder) { true }
        else if (target == @dummy_forwarder_secondary) { false }
        else {
            abort error::invalid_argument(E_UNKNOWN_FORWARDER)
        }
    }

    // ========================== TESTS ==========================

    #[test_only]
    use std::account;
    #[test_only]
    use std::bcs;
    #[test_only]
    use std::signer;

    #[test_only]
    fun setup(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        account::create_account_for_test(signer::address_of(mcms));
        mcms_registry::init_module_for_testing(mcms);
        mcms::mcms_account::init_module_for_testing(mcms);

        primary::init_module_for_testing(fwd);
        secondary::init_module_for_testing(fwd2);
        init_module(adapter);
    }

    #[test_only]
    fun dispatch(function: vector<u8>, data: vector<u8>) {
        let metadata =
            mcms_registry::test_start_dispatch(
                @forwarder_mcms_adapter,
                string::utf8(b"adapter"),
                string::utf8(function),
                data
            );
        mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@forwarder_mcms_adapter);
    }

    #[test_only]
    fun args_target(target: address): vector<u8> {
        bcs::to_bytes(&target)
    }

    #[test_only]
    fun args_target_u64(target: address, v: u64): vector<u8> {
        let out = bcs::to_bytes(&target);
        out.append(bcs::to_bytes(&v));
        out
    }

    #[test_only]
    fun args_target_addr(target: address, a: address): vector<u8> {
        let out = bcs::to_bytes(&target);
        out.append(bcs::to_bytes(&a));
        out
    }

    #[test_only]
    /// Both current owners propose the MCMS owner account; MCMS accepts both via the adapter.
    fun hand_both_to_mcms(owner: &signer, owner2: &signer) {
        let mcms_owner = mcms_owner_address();
        primary::transfer_ownership(owner, mcms_owner);
        secondary::transfer_ownership(owner2, mcms_owner);
        dispatch(b"accept_ownership", args_target(@dummy_forwarder));
        dispatch(b"accept_ownership", args_target(@dummy_forwarder_secondary));
    }

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            fwd2 = @dummy_forwarder_secondary,
            owner = @owner,
            owner2 = @owner_secondary
        )
    ]
    fun test_mcms_controls_both_forwarders(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter, fwd, fwd2);

        hand_both_to_mcms(owner, owner2);
        let mcms_owner = mcms_owner_address();
        assert!(primary::get_owner() == mcms_owner, 1);
        assert!(secondary::get_owner() == mcms_owner, 2);

        // each op only touches its target
        dispatch(b"set_value", args_target_u64(@dummy_forwarder, 42));
        assert!(primary::get_value() == 42, 3);
        assert!(secondary::get_value() == 0, 4);

        dispatch(b"set_value", args_target_u64(@dummy_forwarder_secondary, 43));
        assert!(primary::get_value() == 42, 5);
        assert!(secondary::get_value() == 43, 6);

        // MCMS can hand ownership of one forwarder back out without touching the other
        dispatch(b"transfer_ownership", args_target_addr(@dummy_forwarder_secondary, @owner_secondary));
        secondary::accept_ownership(owner2);
        assert!(secondary::get_owner() == @owner_secondary, 7);
        assert!(primary::get_owner() == mcms_owner, 8);
    }

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            fwd2 = @dummy_forwarder_secondary,
            owner = @owner,
            owner2 = @owner_secondary
        )
    ]
    #[expected_failure(abort_code = 327687, location = dummy_forwarder::forwarder)]
    fun test_old_owner_rejected_primary(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter, fwd, fwd2);
        hand_both_to_mcms(owner, owner2);
        primary::set_value(owner, 1);
    }

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            fwd2 = @dummy_forwarder_secondary,
            owner = @owner,
            owner2 = @owner_secondary
        )
    ]
    #[expected_failure(abort_code = 327687, location = dummy_forwarder_secondary::forwarder)]
    fun test_old_owner_rejected_secondary(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        fwd2: &signer,
        owner: &signer,
        owner2: &signer
    ) {
        setup(mcms, adapter, fwd, fwd2);
        hand_both_to_mcms(owner, owner2);
        secondary::set_value(owner2, 1);
    }

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            fwd2 = @dummy_forwarder_secondary
        )
    ]
    #[expected_failure(abort_code = 327687, location = dummy_forwarder_secondary::forwarder)]
    fun test_set_value_before_ownership_transfer_fails(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter, fwd, fwd2);
        dispatch(b"set_value", args_target_u64(@dummy_forwarder_secondary, 42));
    }

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            fwd2 = @dummy_forwarder_secondary
        )
    ]
    #[expected_failure(abort_code = 65538, location = forwarder_mcms_adapter::adapter)]
    fun test_unknown_forwarder(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter, fwd, fwd2);
        dispatch(b"set_value", args_target_u64(@0xbad, 1));
    }

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            fwd2 = @dummy_forwarder_secondary
        )
    ]
    #[expected_failure(abort_code = 65537, location = forwarder_mcms_adapter::adapter)]
    fun test_unknown_function(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        fwd2: &signer
    ) {
        setup(mcms, adapter, fwd, fwd2);
        dispatch(b"nope", vector[]);
    }
}
