module regulated_token::mcms_regulated_token_registrar {
    use std::object::{Self, Object};
    use std::option::{Self, Option};
    use std::string::{Self, String};

    use mcms::bcs_stream;
    use mcms::mcms_registry;
    use regulated_token::regulated_token;

    const E_UNKNOWN_FUNCTION: u64 = 1;
    const E_NOT_PUBLISHER: u64 = 2;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"MCMS Registrar 1.0.0")
    }

    fun init_module(publisher: &signer) {
        assert!(object::is_object(@regulated_token), E_NOT_PUBLISHER);

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
            mcms_registry::get_callback_params(@regulated_token, McmsCallback {});

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

            regulated_token::initialize(
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

            regulated_token::mint(&caller, to, amount)
        } else if (function_bytes == b"burn") {
            let from = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::burn(&caller, from, amount)
        } else if (function_bytes == b"grant_role") {
            let role_number = bcs_stream::deserialize_u8(&mut stream);
            let account = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::grant_role(&caller, role_number, account)
        } else if (function_bytes == b"revoke_role") {
            let role_number = bcs_stream::deserialize_u8(&mut stream);
            let account = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::revoke_role(&caller, role_number, account)
        } else if (function_bytes == b"freeze_account") {
            let account = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::freeze_account(&caller, account)
        } else if (function_bytes == b"freeze_accounts") {
            let accounts =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::freeze_accounts(&caller, accounts)
        } else if (function_bytes == b"unfreeze_account") {
            let account = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::unfreeze_account(&caller, account)
        } else if (function_bytes == b"unfreeze_accounts") {
            let accounts =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::unfreeze_accounts(&caller, accounts)
        } else if (function_bytes == b"pause") {
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::pause(&caller)
        } else if (function_bytes == b"unpause") {
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::unpause(&caller)
        } else if (function_bytes == b"recover_frozen_funds") {
            let from = bcs_stream::deserialize_address(&mut stream);
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::recover_frozen_funds(&caller, from, to)
        } else if (function_bytes == b"batch_recover_frozen_funds") {
            let accounts =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::batch_recover_frozen_funds(&caller, accounts, to)
        } else if (function_bytes == b"burn_frozen_funds") {
            let from = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::burn_frozen_funds(&caller, from)
        } else if (function_bytes == b"batch_burn_frozen_funds") {
            let accounts =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::batch_burn_frozen_funds(&caller, accounts)
        } else if (function_bytes == b"transfer_admin") {
            let new_admin = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::transfer_admin(&caller, new_admin)
        } else if (function_bytes == b"accept_admin") {
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::accept_admin(&caller)
        } else if (function_bytes == b"recover_tokens") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::recover_tokens(&caller, to)
        } else if (function_bytes == b"apply_role_updates") {
            let role_number = bcs_stream::deserialize_u8(&mut stream);
            let addresses_to_remove =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            let addresses_to_add =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_address(stream)
                );
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::apply_role_updates(
                &caller,
                role_number,
                addresses_to_remove,
                addresses_to_add
            )
        } else if (function_bytes == b"transfer_ownership") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::transfer_ownership(&caller, to)
        } else if (function_bytes == b"accept_ownership") {
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::accept_ownership(&caller)
        } else if (function_bytes == b"execute_ownership_transfer") {
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            regulated_token::execute_ownership_transfer(&caller, to)
        } else {
            abort E_UNKNOWN_FUNCTION
        };

        option::none()
    }

    /// Callable during upgrades
    public(friend) fun register_mcms_entrypoint(publisher: &signer) {
        mcms_registry::register_entrypoint(
            publisher, string::utf8(b"regulated_token"), McmsCallback {}
        );
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
