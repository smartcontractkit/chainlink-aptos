#[test_only]
module regulated_token::mcms_regulated_token_registrar_test {
    use std::account;
    use std::bcs;
    use std::dispatchable_fungible_asset;
    use std::object;
    use std::option;
    use std::primary_fungible_store;
    use std::string::utf8;

    use mcms::mcms_account;
    use mcms::mcms_registry;
    use regulated_token::mcms_regulated_token_registrar as registrar;
    use regulated_token::regulated_token;

    const FREEZER_ROLE: u8 = 2;
    const MINTER_ROLE: u8 = 4;
    const BURNER_ROLE: u8 = 5;
    const RECOVERY_ROLE: u8 = 7;

    const OPERATOR: address = @0x100;
    const USER: address = @0x200;
    const RECIPIENT: address = @0x300;

    fun setup(mcms: &signer, admin: &signer, publisher: &signer) {
        account::create_account_for_test(@mcms);
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        let constructor_ref = object::create_named_object(admin, b"regulated_token");
        account::create_account_if_does_not_exist(
            object::address_from_constructor_ref(&constructor_ref)
        );
        regulated_token::init_module_for_testing(publisher);
        registrar::init_module_for_testing(publisher);
        registrar::test_register_mcms_entrypoint(publisher);
        regulated_token::initialize(
            admin,
            option::none(),
            utf8(b"Regulated Token"),
            utf8(b"RT"),
            6,
            utf8(
                b"https://regulatedtoken.com/images/pic.png"
            ),
            utf8(b"https://regulatedtoken.com")
        );

        let timelock =
            mcms_registry::get_preexisting_code_object_owner_address(@regulated_token);
        regulated_token::grant_role(admin, FREEZER_ROLE, OPERATOR);
        regulated_token::grant_role(admin, MINTER_ROLE, OPERATOR);
        regulated_token::grant_role(admin, BURNER_ROLE, timelock);
        regulated_token::grant_role(admin, RECOVERY_ROLE, timelock);

        let operator = account::create_signer_for_test(OPERATOR);
        regulated_token::mint(&operator, USER, 100);
        regulated_token::freeze_account(&operator, USER);
    }

    /// Run one payload through the registrar inside `derived_supply`, as `mcms::timelock_dispatch` does.
    fun live_dispatch(function: vector<u8>, data: vector<u8>) {
        let metadata =
            mcms_registry::test_start_dispatch(
                @regulated_token,
                utf8(b"regulated_token"),
                utf8(function),
                data
            );
        dispatchable_fungible_asset::derived_supply(metadata);
        mcms_registry::test_finish_dispatch(@regulated_token);
    }

    fun direct_dispatch(function: vector<u8>, data: vector<u8>) {
        let metadata =
            mcms_registry::test_start_dispatch(
                @regulated_token,
                utf8(b"regulated_token"),
                utf8(function),
                data
            );
        registrar::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@regulated_token);
    }

    fun user_balance(): u64 {
        primary_fungible_store::balance(USER, regulated_token::token_metadata())
    }

    #[test(mcms = @mcms, admin = @admin, publisher = @regulated_token)]
    fun test_burn_frozen_funds_direct_call(
        mcms: &signer, admin: &signer, publisher: &signer
    ) {
        setup(mcms, admin, publisher);
        direct_dispatch(b"burn_frozen_funds", bcs::to_bytes(&USER));
        assert!(user_balance() == 0);
    }

    #[test(mcms = @mcms, admin = @admin, publisher = @regulated_token)]
    fun test_burn_frozen_funds_live_dispatch(
        mcms: &signer, admin: &signer, publisher: &signer
    ) {
        setup(mcms, admin, publisher);
        live_dispatch(b"burn_frozen_funds", bcs::to_bytes(&USER));
        assert!(user_balance() == 0);
    }

    #[test(mcms = @mcms, admin = @admin, publisher = @regulated_token)]
    fun test_recover_frozen_funds_live_dispatch(
        mcms: &signer, admin: &signer, publisher: &signer
    ) {
        setup(mcms, admin, publisher);
        let data = bcs::to_bytes(&USER);
        data.append(bcs::to_bytes(&RECIPIENT));
        live_dispatch(b"recover_frozen_funds", data);
        assert!(user_balance() == 0);
        assert!(
            primary_fungible_store::balance(
                RECIPIENT, regulated_token::token_metadata()
            ) == 100
        );
    }

    #[test(mcms = @mcms, admin = @admin, publisher = @regulated_token)]
    fun test_recover_tokens_live_dispatch(
        mcms: &signer, admin: &signer, publisher: &signer
    ) {
        setup(mcms, admin, publisher);
        let operator = account::create_signer_for_test(OPERATOR);
        regulated_token::mint(&operator, @regulated_token, 50);
        live_dispatch(b"recover_tokens", bcs::to_bytes(&RECIPIENT));
        assert!(
            primary_fungible_store::balance(
                RECIPIENT, regulated_token::token_metadata()
            ) == 50
        );
    }

    #[test(mcms = @mcms, admin = @admin, publisher = @regulated_token)]
    fun test_batch_burn_frozen_funds_live_dispatch(
        mcms: &signer, admin: &signer, publisher: &signer
    ) {
        setup(mcms, admin, publisher);
        live_dispatch(b"batch_burn_frozen_funds", bcs::to_bytes(&vector[USER]));
        assert!(user_balance() == 0);
    }

    #[test(mcms = @mcms, admin = @admin, publisher = @regulated_token)]
    fun test_batch_recover_frozen_funds_live_dispatch(
        mcms: &signer, admin: &signer, publisher: &signer
    ) {
        setup(mcms, admin, publisher);
        let data = bcs::to_bytes(&vector[USER]);
        data.append(bcs::to_bytes(&RECIPIENT));
        live_dispatch(b"batch_recover_frozen_funds", data);
        assert!(user_balance() == 0);
    }
}
