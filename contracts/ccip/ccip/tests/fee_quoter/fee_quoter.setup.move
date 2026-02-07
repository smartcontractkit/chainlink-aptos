#[test_only]
module ccip::fee_quoter_setup {
    use std::timestamp;
    use std::account;
    use std::option;
    use std::object::{Self, Object, ExtendRef};
    use std::string::{Self};
    use std::signer;
    use std::primary_fungible_store;
    use std::fungible_asset::{Self, MintRef, BurnRef, TransferRef, Metadata};

    use ccip::state_object;
    use ccip::auth;
    use ccip::fee_quoter;
    use ccip::client;

    const APT_ADDRESS: address =
        @0x000000000000000000000000000000000000000000000000000000000000000a;

    const CHAIN_FAMILY_SELECTOR_EVM: vector<u8> = x"2812d52c";
    const CHAIN_FAMILY_SELECTOR_SVM: vector<u8> = x"1e10bdc4";
    const CHAIN_FAMILY_SELECTOR_APTOS: vector<u8> = x"ac77ffec";

    const EVM_PRECOMPILE_SPACE: u256 = 1024;

    const SVM_EXTRA_ARGS_V1_TAG: vector<u8> = x"1f3b3aba";
    const GENERIC_EXTRA_ARGS_V2_TAG: vector<u8> = x"181dcf10";

    const MOCK_ADDRESS_1: address =
        @0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b;
    const MOCK_ADDRESS_2: address =
        @0x000000000000000000000000F4030086522a5bEEa4988F8cA5B36dbC97BeE88c; // EVM token address
    const MOCK_ADDRESS_3: address =
        @0x8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7;
    const MOCK_ADDRESS_4: address =
        @0x3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d;
    const MOCK_ADDRESS_5: address =
        @0xd1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2;

    const GAS_PRICE_BITS: u8 = 112;

    const MESSAGE_FIXED_BYTES: u64 = 32 * 15;
    const MESSAGE_FIXED_BYTES_PER_TOKEN: u64 = 32 * (4 + (3 + 2));

    const DEST_CHAIN_SELECTOR: u64 = 5678;

    const CCIP_LOCK_OR_BURN_V1_RET_BYTES: u32 = 32;

    const MAX_U64: u256 = 18446744073709551615;
    const MAX_U160: u256 = 1461501637330902918203684832716283019655932542975;
    const MAX_U256: u256 =
        115792089237316195423570985008687907853269984665640564039457584007913129639935;
    const VAL_1E5: u256 = 100_000;
    const VAL_1E14: u256 = 100_000_000_000_000;
    const VAL_1E16: u256 = 10_000_000_000_000_000;
    const VAL_1E18: u256 = 1_000_000_000_000_000_000;

    struct TestToken has key, store {
        metadata: Object<Metadata>,
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    public fun init_timestamp(
        aptos_framework: &signer, timestamp_seconds: u64
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        timestamp::update_global_time_for_test_secs(timestamp_seconds);
    }

    public fun setup(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ): (address, Object<Metadata>) {
        let owner_addr = signer::address_of(owner);
        account::create_account_for_test(signer::address_of(ccip));
        init_timestamp(aptos_framework, 100000);

        // Create object for @ccip
        let _constructor_ref = object::create_named_object(owner, b"ccip");

        state_object::init_module_for_testing(ccip);
        auth::test_init_module(ccip);

        let (token_obj, token_addr) = create_test_token(owner, b"test_token");

        fee_quoter::initialize(
            owner,
            20000000000000,
            token_addr,
            12400,
            vector[token_addr]
        );

        fee_quoter::apply_fee_token_updates(owner, vector[], vector[token_addr]);
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            DEST_CHAIN_SELECTOR, // dest_chain_selector
            vector[token_addr], // add_tokens
            vector[50], // add_min_fee_usd_cents
            vector[500], // add_max_fee_usd_cents
            vector[10], // add_deci_bps - 0.01% (1 bps)
            vector[5000], // add_dest_gas_overhead
            vector[32], // add_dest_bytes_overhead
            vector[true], // add_is_enabled
            vector[] // remove_tokens
        );
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            DEST_CHAIN_SELECTOR, // dest_chain_selector
            true, // is_enabled
            1, // max_number_of_tokens_per_msg
            10000, // max_data_bytes
            7000000, // max_per_msg_gas_limit
            0, // dest_gas_overhead
            0, // dest_gas_per_payload_byte_base
            0, // dest_gas_per_payload_byte_high
            0, // dest_gas_per_payload_byte_threshold
            0, // dest_data_availability_overhead_gas
            0, // dest_gas_per_data_availability_byte
            0, // dest_data_availability_multiplier_bps
            CHAIN_FAMILY_SELECTOR_EVM, // chain_family_selector
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            1, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );
        fee_quoter::apply_premium_multiplier_wei_per_eth_updates(
            owner,
            vector[token_addr], // tokens
            vector[1] // premium_multiplier_wei_per_eth
        );

        // To be able to call token_admin_dispatcher::dispatch_lock_or_burn
        // Need to register onramp signer as an allowed onramp
        auth::apply_allowed_onramp_updates(
            owner,
            vector[], // onramps_to_remove
            vector[signer::address_of(ccip)] // onramps_to_add
        );

        // To be able to call fee_quoter::update_prices, need to register as an allowed offramp
        auth::apply_allowed_offramp_updates(
            owner,
            vector[], // offramps_to_remove
            vector[owner_addr] // offramps_to_add
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[DEST_CHAIN_SELECTOR], // gas_dest_chain_selectors
            vector[0] // gas_usd_per_unit_gas
        );

        (owner_addr, token_obj)
    }

    public fun create_test_token(owner: &signer, seed: vector<u8>)
        : (Object<Metadata>, address) {
        let constructor_ref = object::create_named_object(owner, seed);

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            option::none(), // maximum supply
            string::utf8(seed), // name
            string::utf8(seed), // symbol
            0, // decimals
            string::utf8(b"http://www.example.com/favicon.ico"), // icon uri
            string::utf8(b"http://www.example.com") // project uri
        );

        let metadata = object::object_from_constructor_ref(&constructor_ref);

        // ======================== Create token pool ========================
        let token_addr = object::object_address(&metadata);

        // =========== Create token refs ==================

        let obj_signer = object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor_ref);
        let transfer_ref = fungible_asset::generate_transfer_ref(&constructor_ref);
        move_to(
            &obj_signer,
            TestToken {
                metadata,
                extend_ref,
                mint_ref,
                burn_ref,
                transfer_ref
            }
        );

        (metadata, token_addr)
    }

    // Helper to create an EVM-compatible receiver address
    public fun create_evm_receiver_address(): vector<u8> {
        x"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    }

    // Helper to create generic extra args with gas limit
    public fun create_extra_args(gas_limit: u64, strict_mode: bool): vector<u8> {
        client::encode_generic_extra_args_v2(gas_limit as u256, strict_mode)
    }

    // Helper to set up token and gas prices
    public fun setup_prices(
        owner: &signer, token_addr: address, token_price: u256, gas_price: u256
    ) {
        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[token_price], // source_usd_per_token
            vector[DEST_CHAIN_SELECTOR], // gas_dest_chain_selectors
            vector[gas_price] // gas_usd_per_unit_gas
        );
    }

    // Helper function for setting up dest chain configs
    public fun setup_dest_chain_config(
        owner: &signer,
        dest_chain_selector: u64,
        chain_family_selector: vector<u8>,
        with_gas_settings: bool
    ) {
        // Calculate gas settings based on whether we need gas or not
        let (
            dest_gas_overhead,
            dest_gas_per_payload_byte_base,
            dest_gas_per_payload_byte_high,
            dest_gas_per_payload_byte_threshold,
            dest_data_availability_overhead_gas,
            dest_gas_per_data_availability_byte,
            dest_data_availability_multiplier_bps,
            default_token_fee_usd_cents,
            default_token_dest_gas_overhead,
            gas_multiplier_wei_per_eth,
            network_fee_usd_cents
        ) =
            if (with_gas_settings)
                (
                    10000, // dest_gas_overhead
                    20, // dest_gas_per_payload_byte_base
                    30, // dest_gas_per_payload_byte_high
                    2000, // dest_gas_per_payload_byte_threshold
                    50000, // dest_data_availability_overhead_gas
                    60, // dest_gas_per_data_availability_byte
                    1000, // dest_data_availability_multiplier_bps
                    200, // default_token_fee_usd_cents
                    30000, // default_token_dest_gas_overhead
                    3000000, // gas_multiplier_wei_per_eth
                    100 // network_fee_usd_cents
                )
            else
                (
                    0, // dest_gas_overhead
                    0, // dest_gas_per_payload_byte_base
                    0, // dest_gas_per_payload_byte_high
                    0, // dest_gas_per_payload_byte_threshold
                    0, // dest_data_availability_overhead_gas
                    0, // dest_gas_per_data_availability_byte
                    0, // dest_data_availability_multiplier_bps
                    0, // default_token_fee_usd_cents
                    0, // default_token_dest_gas_overhead
                    1, // gas_multiplier_wei_per_eth
                    0 // network_fee_usd_cents
                );

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            dest_chain_selector, // dest_chain_selector
            true, // is_enabled
            5, // max_number_of_tokens_per_msg
            15000, // max_data_bytes
            6000000, // max_per_msg_gas_limit
            dest_gas_overhead,
            dest_gas_per_payload_byte_base,
            dest_gas_per_payload_byte_high,
            dest_gas_per_payload_byte_threshold,
            dest_data_availability_overhead_gas,
            dest_gas_per_data_availability_byte,
            dest_data_availability_multiplier_bps,
            chain_family_selector,
            true, // enforce_out_of_order
            default_token_fee_usd_cents,
            default_token_dest_gas_overhead,
            2000000, // default_tx_gas_limit
            gas_multiplier_wei_per_eth,
            20000000, // gas_price_staleness_threshold
            network_fee_usd_cents
        );
    }

    // Add token transfer fee config helper
    public fun setup_token_transfer_fee_config(
        owner: &signer,
        dest_chain_selector: u64,
        token_addr: address,
        min_fee_usd_cents: u32,
        max_fee_usd_cents: u32,
        deci_bps: u16
    ) {
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            dest_chain_selector, // dest_chain_selector
            vector[token_addr], // add_tokens
            vector[min_fee_usd_cents], // add_min_fee_usd_cents
            vector[max_fee_usd_cents], // add_max_fee_usd_cents
            vector[deci_bps], // add_deci_bps - percentage in deci basis points
            vector[10000], // add_dest_gas_overhead
            vector[128], // add_dest_bytes_overhead
            vector[true], // add_is_enabled
            vector[] // remove_tokens
        );
    }

    // =========== Constant Getters ============
    public fun get_dest_chain_selector(): u64 {
        DEST_CHAIN_SELECTOR
    }

    public fun get_apt_address(): address {
        APT_ADDRESS
    }

    public fun get_chain_family_selector_evm(): vector<u8> {
        CHAIN_FAMILY_SELECTOR_EVM
    }

    public fun get_chain_family_selector_svm(): vector<u8> {
        CHAIN_FAMILY_SELECTOR_SVM
    }

    public fun get_chain_family_selector_aptos(): vector<u8> {
        CHAIN_FAMILY_SELECTOR_APTOS
    }

    public fun get_evm_precompile_space(): u256 {
        EVM_PRECOMPILE_SPACE
    }

    public fun get_svm_extra_args_v1_tag(): vector<u8> {
        SVM_EXTRA_ARGS_V1_TAG
    }

    public fun get_generic_extra_args_v2_tag(): vector<u8> {
        GENERIC_EXTRA_ARGS_V2_TAG
    }

    public fun get_mock_address_1(): address {
        MOCK_ADDRESS_1
    }

    public fun get_mock_address_2(): address {
        MOCK_ADDRESS_2
    }

    public fun get_mock_address_3(): address {
        MOCK_ADDRESS_3
    }

    public fun get_mock_address_4(): address {
        MOCK_ADDRESS_4
    }

    public fun get_mock_address_5(): address {
        MOCK_ADDRESS_5
    }

    public fun get_gas_price_bits(): u8 {
        GAS_PRICE_BITS
    }

    public fun get_message_fixed_bytes(): u64 {
        MESSAGE_FIXED_BYTES
    }

    public fun get_message_fixed_bytes_per_token(): u64 {
        MESSAGE_FIXED_BYTES_PER_TOKEN
    }

    public fun get_max_u64(): u256 {
        MAX_U64
    }

    public fun get_max_u160(): u256 {
        MAX_U160
    }

    public fun get_max_u256(): u256 {
        MAX_U256
    }

    public fun get_val_1e5(): u256 {
        VAL_1E5
    }

    public fun get_val_1e14(): u256 {
        VAL_1E14
    }

    public fun get_val_1e16(): u256 {
        VAL_1E16
    }

    public fun get_val_1e18(): u256 {
        VAL_1E18
    }

    public fun get_ccip_lock_or_burn_v1_ret_bytes(): u32 {
        CCIP_LOCK_OR_BURN_V1_RET_BYTES
    }
}
