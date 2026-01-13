#[test_only]
module ccip_token_pool::token_pool_test {
    use std::account;
    use std::signer;
    use std::object;
    use std::option;
    use std::string;
    use std::primary_fungible_store;
    use std::fungible_asset;
    use ccip_token_pool::token_pool::TokenPoolState;

    use ccip_token_pool::token_pool;

    struct TestToken has key {}

    const Decimals: u8 = 8;
    const OwnerInitbalance: u64 = 1_000_000;

    const DefaultRemoteChain: u64 = 2000;
    const DefaultRemoteToken: vector<u8> = b"default_remote_token";
    const DefaultRemotePool: vector<u8> = b"default_remote_pool";

    #[test(owner = @ccip_token_pool)]
    fun initialize_correctly_sets_state(owner: &signer) {
        let state = set_up_test(owner);

        assert!(token_pool::get_token_decimals(&state) == Decimals);
        assert!(token_pool::is_supported_chain(&state, DefaultRemoteChain));

        token_pool::destroy_token_pool(state);
    }

    #[test(owner = @ccip_token_pool)]
    fun add_remote_pool_existing_chain(owner: &signer) {
        let state = set_up_test(owner);
        let new_remote_pool = b"new_pool";

        assert!(
            !token_pool::is_remote_pool(&state, DefaultRemoteChain, new_remote_pool)
        );
        assert!(token_pool::get_remote_pools(&state, DefaultRemoteChain).length() == 1);

        token_pool::add_remote_pool(&mut state, DefaultRemoteChain, new_remote_pool);

        assert!(token_pool::is_remote_pool(&state, DefaultRemoteChain, new_remote_pool));
        assert!(token_pool::get_remote_pools(&state, DefaultRemoteChain).length() == 2);

        token_pool::destroy_token_pool(state);
    }

    #[test]
    fun test_calculate_local_amount_same_decimals() {
        // When remote and local decimals are the same, amount should not change
        let remote_amount: u256 = 1000000;
        let remote_decimals: u8 = 8;
        let local_decimals: u8 = 8;

        let local_amount =
            token_pool::calculate_local_amount(
                remote_amount, remote_decimals, local_decimals
            );
        assert!(local_amount == 1000000, 0);
    }

    #[test]
    fun test_calculate_local_amount_more_decimals() {
        // When local has more decimals, amount should increase
        let remote_amount: u256 = 1000000;
        let remote_decimals: u8 = 6; // 6 decimals
        let local_decimals: u8 = 8; // 8 decimals (2 more)

        let local_amount =
            token_pool::calculate_local_amount(
                remote_amount, remote_decimals, local_decimals
            );
        assert!(local_amount == 100000000, 0); // 1000000 * 10^2
    }

    #[test]
    fun test_calculate_local_amount_fewer_decimals() {
        // When local has fewer decimals, amount should decrease
        let remote_amount: u256 = 1000000;
        let remote_decimals: u8 = 8; // 8 decimals
        let local_decimals: u8 = 6; // 6 decimals (2 fewer)

        let local_amount =
            token_pool::calculate_local_amount(
                remote_amount, remote_decimals, local_decimals
            );
        assert!(local_amount == 10000, 0); // 1000000 / 10^2
    }

    #[test]
    #[expected_failure(abort_code = 196619, location = ccip_token_pool::token_pool)]
    fun test_decimal_overflow_protection() {
        // Test for overflow protection - when decimal difference exceeds MAX_SAFE_DECIMAL_DIFF
        let remote_amount: u256 = 1000000;
        let remote_decimals: u8 = 1; // 1 decimal
        let local_decimals: u8 = 100; // 100 decimals (99 more - exceeds the limit of 77)

        // E_DECIMAL_OVERFLOW error
        let _local_amount =
            token_pool::calculate_local_amount(
                remote_amount, remote_decimals, local_decimals
            );
    }

    #[test]
    #[expected_failure(abort_code = 196618, location = ccip_token_pool::token_pool)]
    fun test_local_amount_u64_overflow() {
        let remote_amount: u256 = 0xffffffffffffffffffffffffffffffff;
        let remote_decimals: u8 = 0;
        let local_decimals: u8 = 18;

        // E_INVALID_ENCODED_AMOUNT error
        let _local_amount =
            token_pool::calculate_local_amount(
                remote_amount, remote_decimals, local_decimals
            );
    }

    // ================================================================
    // |                           Setup                              |
    // ================================================================
    inline fun set_up_test(owner: &signer): token_pool::TokenPoolState {
        let signer_address = signer::address_of(owner);
        account::create_account_for_test(signer_address);

        let constructor_ref = &object::create_named_object(owner, b"CCIPTokenPool");
        move_to(owner, TestToken {});

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            option::none(),
            string::utf8(b"TEST"),
            string::utf8(b"TEST"),
            Decimals,
            string::utf8(b""),
            string::utf8(b"")
        );

        let fungible_asset_mint_ref = fungible_asset::generate_mint_ref(constructor_ref);

        primary_fungible_store::mint(
            &fungible_asset_mint_ref, signer_address, OwnerInitbalance
        );

        let token_address = object::address_from_constructor_ref(constructor_ref);

        let state = token_pool::initialize(owner, token_address, vector[]);

        // Set state in the pool
        set_up_default_remote_chain(&mut state);

        state
    }

    inline fun set_up_default_remote_chain(state: &mut TokenPoolState) {
        token_pool::apply_chain_updates(
            state,
            vector[],
            vector[DefaultRemoteChain],
            vector[vector[DefaultRemotePool]],
            vector[DefaultRemoteToken]
        )
    }
}
