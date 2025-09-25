#[test_only]
module regulated_token::initialization_test {
    use std::account;
    use std::object::{Self};
    use std::option::{Self};
    use std::signer;
    use std::string::{Self};

    use regulated_token::regulated_token::{Self};

    const MAX_SUPPLY: u128 = 1000000;
    const DECIMALS: u8 = 8;
    const ICON: vector<u8> = b"http://chainlink.com/regulated-icon.png";
    const PROJECT: vector<u8> = b"ChainLink Regulated Token Project";
    const NAME: vector<u8> = b"Regulated ChainLink Token";
    const SYMBOL: vector<u8> = b"RLINK";

    fun setup(admin: &signer, regulated_token: &signer) {
        let constructor_ref = object::create_named_object(admin, b"regulated_token");
        account::create_account_if_does_not_exist(
            object::address_from_constructor_ref(&constructor_ref)
        );
        account::create_account_for_test(signer::address_of(regulated_token));

        regulated_token::init_module_for_testing(regulated_token);

    }

    fun initialize_regulated_token(
        admin: &signer, max_supply: option::Option<u128>
    ) {
        regulated_token::initialize(
            admin,
            max_supply,
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON),
            string::utf8(PROJECT)
        );
    }

    #[test(admin = @admin, user = @0xface, regulated_token = @regulated_token)]
    #[expected_failure(abort_code = 327683, location = regulated_token::ownable)]
    public fun test_unauthorized_initialize(
        admin: &signer, user: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        // Attempt unauthorized initialize (should fail) E_NOT_ADMIN
        initialize_regulated_token(user, option::some(MAX_SUPPLY));
    }

    #[test(admin = @admin, regulated_token = @regulated_token)]
    #[
        expected_failure(
            abort_code = regulated_token::regulated_token::E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED,
            location = regulated_token::regulated_token
        )
    ]
    public fun test_initialize_with_same_symbol_fails(
        admin: &signer, regulated_token: &signer
    ) {
        setup(admin, regulated_token);

        initialize_regulated_token(admin, option::some(MAX_SUPPLY));

        // Second initialization (should fail)
        regulated_token::initialize(
            admin,
            option::none(),
            string::utf8(b"USDC Token"),
            string::utf8(b"USDC"),
            DECIMALS,
            string::utf8(ICON),
            string::utf8(PROJECT)
        );
    }
}
