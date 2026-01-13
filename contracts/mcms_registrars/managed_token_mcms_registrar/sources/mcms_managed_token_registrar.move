module managed_token::mcms_managed_token_registrar {
    use std::object::{Self, Object};
    use std::option::{Self, Option};
    use std::string::{Self, String};

    use mcms::bcs_stream;
    use mcms::mcms_registry;
    use managed_token::managed_token;

    const E_UNKNOWN_FUNCTION: u64 = 1;
    const E_NOT_PUBLISHER: u64 = 2;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"MCMS Registrar 1.0.0")
    }

    fun init_module(publisher: &signer) {
        assert!(object::is_object(@managed_token), E_NOT_PUBLISHER);

        if (@mcms_register_entrypoints == @0x1) {
            register_mcms_entrypoint(publisher);
        };
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================
    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(_metadata: Object<T>): Option<u128> {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@managed_token, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let max_supply =
                bcs_stream::deserialize_option(
                    &mut stream, |stream| bcs_stream::deserialize_u128(stream)
                );
            let name = bcs_stream::deserialize_string(&mut stream);
            let symbol = bcs_stream::deserialize_string(&mut stream);
            let decimals = bcs_stream::deserialize_u8(&mut stream);
            let icon = bcs_stream::deserialize_string(&mut stream);
            let project = bcs_stream::deserialize_string(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            managed_token::initialize(
                &caller,
                max_supply,
                name,
                symbol,
                decimals,
                icon,
                project
            )
        } else if (function_bytes == b"mint") {
            let to = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            managed_token::mint(&caller, to, amount)
        } else if (function_bytes == b"burn") {
            let from = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            managed_token::burn(&caller, from, amount)
        } else if (function_bytes == b"apply_allowed_minter_updates") {
            let minters_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let minters_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            managed_token::apply_allowed_minter_updates(
                &caller, minters_to_remove, minters_to_add
            )
        } else if (function_bytes == b"apply_allowed_burner_updates") {
            let burners_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let burners_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            managed_token::apply_allowed_burner_updates(
                &caller, burners_to_remove, burners_to_add
            )
        } else if (function_bytes == b"transfer_ownership") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            managed_token::transfer_ownership(&caller, to)
        } else if (function_bytes == b"accept_ownership") {
            bcs_stream::assert_is_consumed(&stream);

            managed_token::accept_ownership(&caller)
        } else if (function_bytes == b"execute_ownership_transfer") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            managed_token::execute_ownership_transfer(&caller, to)
        } else {
            abort E_UNKNOWN_FUNCTION
        };

        option::none()
    }

    /// Callable during upgrades
    public(friend) fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"managed_token"), McmsCallback {}
        );
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
