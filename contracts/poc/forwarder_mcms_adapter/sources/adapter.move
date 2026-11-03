/// MCMS adapter for dummy_forwarder::forwarder.
///
/// MCMS reaches this module through the dispatchable FA hook (no compile-time dependency on us),
/// and this module statically calls the forwarder's public entry functions using the signer of
/// the MCMS owner resource account registered for this package. Making that account the
/// forwarder's owner gives MCMS control of the forwarder without changing the forwarder's code.
module forwarder_mcms_adapter::adapter {
    use std::error;
    use std::object::Object;
    use std::option::{Self, Option};
    use std::string;

    use mcms::bcs_stream;
    use mcms::mcms_registry;

    use dummy_forwarder::forwarder;

    const E_UNKNOWN_FUNCTION: u64 = 1;

    struct McmsCallback has drop {}

    fun init_module(publisher: &signer) {
        register_mcms_entrypoint(publisher);
    }

    #[view]
    /// The address MCMS signs as when calling through this adapter. The forwarder owner must be
    /// set to this address.
    public fun mcms_owner_address(): address {
        mcms_registry::get_registered_owner_address(@forwarder_mcms_adapter)
    }

    public fun mcms_entrypoint<T: key>(_metadata: Object<T>): Option<u128> {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@forwarder_mcms_adapter, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"set_value") {
            let value = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            forwarder::set_value(&caller, value)
        } else if (function_bytes == b"transfer_ownership") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            forwarder::transfer_ownership(&caller, to)
        } else if (function_bytes == b"accept_ownership") {
            bcs_stream::assert_is_consumed(&stream);
            forwarder::accept_ownership(&caller)
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"adapter"), McmsCallback {}
        );
    }

    #[test_only]
    use std::account;
    #[test_only]
    use std::bcs;
    #[test_only]
    use std::signer;

    #[test_only]
    fun setup(mcms: &signer, adapter: &signer, fwd: &signer) {
        account::create_account_for_test(signer::address_of(mcms));
        mcms_registry::init_module_for_testing(mcms);
        mcms::mcms_account::init_module_for_testing(mcms);

        forwarder::init_module_for_testing(fwd);
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

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            owner = @owner
        )
    ]
    fun test_mcms_controls_forwarder(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        owner: &signer
    ) {
        setup(mcms, adapter, fwd);

        let mcms_owner = mcms_owner_address();
        assert!(
            mcms_owner
                == mcms_registry::get_preexisting_code_object_owner_address(
                    @forwarder_mcms_adapter
                ),
            1
        );

        // current owner proposes the MCMS owner account, MCMS accepts via the adapter
        forwarder::transfer_ownership(owner, mcms_owner);
        dispatch(b"accept_ownership", vector[]);
        assert!(forwarder::get_owner() == mcms_owner, 2);

        dispatch(b"set_value", bcs::to_bytes(&42u64));
        assert!(forwarder::get_value() == 42, 3);

        // MCMS can hand ownership back out
        dispatch(b"transfer_ownership", bcs::to_bytes(&@owner));
        forwarder::accept_ownership(owner);
        assert!(forwarder::get_owner() == @owner, 4);
    }

    #[
        test(
            mcms = @mcms,
            adapter = @forwarder_mcms_adapter,
            fwd = @dummy_forwarder,
            owner = @owner
        )
    ]
    #[expected_failure(abort_code = 327687, location = dummy_forwarder::forwarder)]
    fun test_old_owner_rejected(
        mcms: &signer,
        adapter: &signer,
        fwd: &signer,
        owner: &signer
    ) {
        setup(mcms, adapter, fwd);
        forwarder::transfer_ownership(owner, mcms_owner_address());
        dispatch(b"accept_ownership", vector[]);

        forwarder::set_value(owner, 1);
    }

    #[test(mcms = @mcms, adapter = @forwarder_mcms_adapter, fwd = @dummy_forwarder)]
    #[expected_failure(abort_code = 327687, location = dummy_forwarder::forwarder)]
    fun test_set_value_before_ownership_transfer_fails(
        mcms: &signer, adapter: &signer, fwd: &signer
    ) {
        setup(mcms, adapter, fwd);
        dispatch(b"set_value", bcs::to_bytes(&42u64));
    }

    #[test(mcms = @mcms, adapter = @forwarder_mcms_adapter, fwd = @dummy_forwarder)]
    #[expected_failure(abort_code = 65537, location = forwarder_mcms_adapter::adapter)]
    fun test_unknown_function(
        mcms: &signer, adapter: &signer, fwd: &signer
    ) {
        setup(mcms, adapter, fwd);
        dispatch(b"nope", vector[]);
    }
}
