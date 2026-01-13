#[test_only]
module ccip::fee_quoter_errors {
    use std::object;
    use std::vector;
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;
    use std::timestamp;
    use ccip::client;

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65539, location = ccip::fee_quoter) // E_UNKNOWN_DEST_CHAIN_SELECTOR
    ]
    fun test_chain_not_configured(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        let non_existent_chain = 123456789;

        // Attempt to get fee for non-existent chain - E_UNKNOWN_DEST_CHAIN_SELECTOR
        fee_quoter::get_validated_fee(
            non_existent_chain, // chain that doesn't exist
            fee_quoter_setup::create_evm_receiver_address(), // receiver
            b"test data", // data
            vector[], // token addresses
            vector[], // token amounts
            vector[], // token store addresses
            token_addr, // fee token
            @0x0, // fee token store
            fee_quoter_setup::create_extra_args(500000, true) // extra args
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 196620, location = ccip::fee_quoter) // Different error code than expected
    ]
    fun test_stale_gas_price(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Change chain's gas price staleness threshold to a small value
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(), // dest_chain_selector
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
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            0, // gas_multiplier_wei_per_eth
            10, // gas_price_staleness_threshold - Very short staleness (10 seconds)
            0 // network_fee_usd_cents
        );

        // Update timestamp to make gas price stale (many seconds into the future)
        timestamp::update_global_time_for_test_secs(10000000);

        // This should fail with E_STALE_GAS_PRICE
        fee_quoter::get_validated_fee(
            fee_quoter_setup::get_dest_chain_selector(),
            fee_quoter_setup::create_evm_receiver_address(), // receiver
            b"test data", // data
            vector[], // token addresses
            vector[], // token amounts
            vector[], // token store addresses
            token_addr, // fee token
            @0x0, // fee token store
            fee_quoter_setup::create_extra_args(500000, true) // extra args
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65564, location = ccip::fee_quoter) // E_INVALID_CHAIN_FAMILY_SELECTOR
    ]
    fun test_token_transfer_chain_family_auth_required(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let _token_addr = object::object_address(&token_obj);

        // Create a token to transfer
        let (_transfer_token_obj, _transfer_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"transfer_token");

        // Create a chain with chain family that requires token receiver auth
        let chain_selector = 88888;

        // Aptos chain family requires token receiver auth
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            chain_selector, // dest_chain_selector
            true, // is_enabled
            5, // max_number_of_tokens_per_msg
            10000, // max_data_bytes
            7000000, // max_per_msg_gas_limit
            0, // dest_gas_overhead
            0, // dest_gas_per_payload_byte_base
            0, // dest_gas_per_payload_byte_high
            0, // dest_gas_per_payload_byte_threshold
            0, // dest_data_availability_overhead_gas
            0, // dest_gas_per_data_availability_byte
            0, // dest_data_availability_multiplier_bps
            x"abc123", // chain_family_selector ===================== (INVALID)
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            0, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65558, location = ccip::fee_quoter) // E_INVALID_TOKEN_RECEIVER
    ]
    fun test_invalid_token_receiver(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up SVM chain config
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            true, // is_enabled
            5, // max_number_of_tokens_per_msg
            10000, // max_data_bytes
            7000000, // max_per_msg_gas_limit
            0, // dest_gas_overhead
            0, // dest_gas_per_payload_byte_base
            0, // dest_gas_per_payload_byte_high
            0, // dest_gas_per_payload_byte_threshold
            0, // dest_data_availability_overhead_gas
            0, // dest_gas_per_data_availability_byte
            0, // dest_data_availability_multiplier_bps
            fee_quoter_setup::get_chain_family_selector_svm(), // chain_family_selector
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            0, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[fee_quoter_setup::get_dest_chain_selector()], // gas_dest_chain_selectors
            vector[1000] // gas_usd_per_unit_gas
        );

        // Create SVM extra args with invalid token receiver
        let invalid_receiver = vector::empty<u8>(); // All zeros - invalid for token receiver
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut invalid_receiver, 0u8);
            i = i + 1;
        };
        let extra_args =
            client::encode_svm_extra_args_v1(
                500000, // compute_units
                0, // account_is_writable_bitmap
                true, // allow_out_of_order_execution
                invalid_receiver, // token_receiver (all zeros)
                vector[] // accounts
            );

        // This should fail with E_INVALID_TOKEN_RECEIVER since we're sending tokens
        // but the token receiver is all zeros (invalid)
        let _ =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                x"7e5f4552091a69125d5dfcb7b8c2659029395bdf9c45bb0f8a496b606328c3ef", // Some valid receiver
                b"test",
                vector[token_addr], // token_addresses - sending tokens requires valid token receiver
                vector[100], // token_amounts
                vector[@0x0], // token_store_addresses
                token_addr, // fee_token
                @0x0, // fee_token_store
                extra_args
            );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65550, location = ccip::fee_quoter) // E_UNSUPPORTED_NUMBER_OF_TOKENS
    ]
    fun test_too_many_tokens(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create multiple tokens to transfer
        let (_token1_obj, token1_addr) =
            fee_quoter_setup::create_test_token(owner, b"token1");
        let (_token2_obj, token2_addr) =
            fee_quoter_setup::create_test_token(owner, b"token2");
        let (_token3_obj, token3_addr) =
            fee_quoter_setup::create_test_token(owner, b"token3");

        // Configure destination chain with low max tokens limit
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            true, // is_enabled
            2, // max_number_of_tokens_per_msg - Only 2 tokens allowed
            10000, // max_data_bytes
            7000000, // max_per_msg_gas_limit
            0, // dest_gas_overhead
            0, // dest_gas_per_payload_byte_base
            0, // dest_gas_per_payload_byte_high
            0, // dest_gas_per_payload_byte_threshold
            0, // dest_data_availability_overhead_gas
            0, // dest_gas_per_data_availability_byte
            0, // dest_data_availability_multiplier_bps
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            0, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );

        // Attempt to calculate fee for 3 tokens when limit is 2
        // This should fail with E_UNSUPPORTED_NUMBER_OF_TOKENS
        fee_quoter::get_validated_fee(
            fee_quoter_setup::get_dest_chain_selector(),
            fee_quoter_setup::create_evm_receiver_address(), // receiver
            b"test data", // data
            vector[token1_addr, token2_addr, token3_addr], // 3 token addresses
            vector[100, 200, 300], // 3 token amounts
            vector[@0x0, @0x0, @0x0], // 3 token destinations
            token_addr, // fee token
            @0x0, // fee token store
            fee_quoter_setup::create_extra_args(500000, true) // extra args
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65549, location = ccip::fee_quoter) // E_MESSAGE_TOO_LARGE
    ]
    fun test_message_too_large_reverts(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create extra args with gas limit
        let extra_args = client::encode_generic_extra_args_v2(500000, true);

        // Create oversized data (exceeds max_data_bytes of 10000 set in setup)
        let oversized_data = vector[];
        let i = 0;
        while (i < 15000) { // Exceeds the 10000 limit set in setup
            oversized_data.push_back((i % 256) as u8);
            i = i + 1;
        };

        // Create EVM-compatible receiver address
        let receiver =
            x"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

        // This should fail with E_MESSAGE_TOO_LARGE
        fee_quoter::get_validated_fee(
            fee_quoter_setup::get_dest_chain_selector(),
            receiver,
            oversized_data, // Too large data
            vector[], // token addresses
            vector[], // token amounts
            vector[], // token store addresses
            token_addr, // fee token
            @0x0, // fee token store (not used in test)
            extra_args // extra args
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65554, location = ccip::fee_quoter) // E_MESSAGE_GAS_LIMIT_TOO_HIGH
    ]
    fun test_gas_limit_too_high(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);
        let dest_chain_selector = fee_quoter_setup::get_dest_chain_selector();
        // Set up destination chain config
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            dest_chain_selector,
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            true // is_enabled
        );

        // Set up token prices
        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[dest_chain_selector], // gas_dest_chain_selectors
            vector[1000] // gas_usd_per_unit_gas
        );

        // Set up token transfer fee config
        fee_quoter_setup::setup_token_transfer_fee_config(
            owner,
            dest_chain_selector,
            token_addr, // fee_token
            50, // min_fee_usd_cent
            500, // max_fee_usd_cent
            25 // deci_bp
        );

        let receiver =
            x"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

        // Get the max gas limit from the config
        let config = fee_quoter::get_dest_chain_config(dest_chain_selector);
        let (
            _, _, _, max_gas_limit, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _
        ) = fee_quoter::dest_chain_config_values(config);

        // Try with a gas limit that's too high (max + 1)
        let _ =
            fee_quoter::get_validated_fee(
                dest_chain_selector,
                receiver,
                b"test",
                vector[], // token addresses
                vector[], // token amounts
                vector[], // token store addresses
                token_addr, // fee token
                @0x0, // fee token store
                client::encode_generic_extra_args_v2((max_gas_limit + 1 as u256), true) // extra args
            );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65556, location = ccip::fee_quoter) // E_INVALID_EXTRA_ARGS_TAG
    ]
    fun test_invalid_extra_args_data(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        let dest_chain_selector = fee_quoter_setup::get_dest_chain_selector();
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            dest_chain_selector,
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            true // is_enabled
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[dest_chain_selector], // gas_dest_chain_selectors
            vector[1000] // gas_usd_per_unit_gas
        );

        fee_quoter_setup::setup_token_transfer_fee_config(
            owner,
            dest_chain_selector,
            token_addr, // fee_token
            50, // min_fee_usd_cent
            500, // max_fee_usd_cent
            25 // deci_bp
        );

        let receiver =
            x"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

        // Create invalid extra args with truncated data
        let extra_args = vector[];
        vector::push_back(&mut extra_args, 0u8); // Valid EVM tag

        // Just a few bytes, not enough for a full gas limit
        vector::push_back(&mut extra_args, 0u8);
        vector::push_back(&mut extra_args, 0u8);
        vector::push_back(&mut extra_args, 0u8);
        vector::push_back(&mut extra_args, 0u8);

        // This should fail with E_INVALID_EXTRA_ARGS_DATA
        let _ =
            fee_quoter::get_validated_fee(
                dest_chain_selector,
                receiver,
                b"test",
                vector[], // token_addresses
                vector[], // token_amounts
                vector[], // token_store_addresses
                token_addr, // fee_token
                @0x0, // fee_token_store
                extra_args
            );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65559, location = ccip::fee_quoter) // E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH
    ]
    fun test_message_compute_unit_limit_too_high(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        let dest_chain_selector = fee_quoter_setup::get_dest_chain_selector();

        // Create SVM chain config with max compute units of 5000000
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            dest_chain_selector,
            fee_quoter_setup::get_chain_family_selector_svm(), // chain_family_selector
            true // is_enabled
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[dest_chain_selector], // gas_dest_chain_selectors
            vector[1000] // gas_usd_per_unit_gas
        );

        // Get the destination chain config to check max compute units
        let config = fee_quoter::get_dest_chain_config(dest_chain_selector);
        let (
            _, _, _, max_gas_limit, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _
        ) = fee_quoter::dest_chain_config_values(config);

        // Create SVM extra args with compute units exceeding the max
        let extra_args =
            client::encode_svm_extra_args_v1(
                max_gas_limit + 1, // compute_units - exceeds max
                0, // account_is_writable_bitmap
                true, // allow_out_of_order_execution
                x"7e5f4552091a69125d5dfcb7b8c2659029395bdf9c45bb0f8a496b606328c3ef", // token_receiver
                vector[] // accounts
            );

        // This should fail with E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH
        let _ =
            fee_quoter::get_validated_fee(
                dest_chain_selector,
                x"7e5f4552091a69125d5dfcb7b8c2659029395bdf9c45bb0f8a496b606328c3ef",
                b"test",
                vector[], // token_addresses
                vector[], // token_amounts
                vector[], // token_store_addresses
                token_addr, // fee_token
                @0x0, // fee_token_store
                extra_args
            );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65561, location = ccip::fee_quoter) // E_SOURCE_TOKEN_DATA_TOO_LARGE
    ]
    fun test_source_token_data_too_large(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up destination chain config and token transfer fee config
        let dest_chain_selector = fee_quoter_setup::get_dest_chain_selector();
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            dest_chain_selector,
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            true // is_enabled
        );

        // 33 is 1 greater than CCIP_LOCK_OR_BURN_V1_RET_BYTES
        let add_dest_bytes_overhead = 33;

        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            dest_chain_selector,
            vector[token_addr], // add_tokens
            vector[50u32], // add_min_fee_usd_cents
            vector[500u32], // add_max_fee_usd_cents
            vector[25u16], // add_deci_bps
            vector[5u32], // add_dest_gas_overhead
            vector[add_dest_bytes_overhead], // add_dest_bytes_overhead
            vector[true], // add_is_enabled
            vector[] // remove_tokens
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[dest_chain_selector], // gas_dest_chain_selectors
            vector[1000] // gas_usd_per_unit_gas
        );

        // Create pool data that's too large for dest_bytes_overhead
        // Call process_message_args with the large pool data
        let dest_token_addresses = vector[
            x"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        ];

        // Create a large vector of zeros for pool data
        let large_pool_data = vector::empty<u8>();
        for (i in 0..(add_dest_bytes_overhead + 1)) {
            vector::push_back(&mut large_pool_data, 0u8);
        };

        // This should fail with E_SOURCE_TOKEN_DATA_TOO_LARGE
        fee_quoter::process_message_args(
            dest_chain_selector,
            token_addr,
            1000, // fee_token_amount
            client::encode_generic_extra_args_v2(500000, true),
            vector[token_addr], // local_token_addresses,
            dest_token_addresses,
            vector[large_pool_data] // dest_pool_datas
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65571, location = ccip::fee_quoter) // E_INVALID_DEST_BYTES_OVERHEAD
    ]
    fun test_invalid_dest_bytes_overhead(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up destination chain config and token transfer fee config
        let dest_chain_selector = fee_quoter_setup::get_dest_chain_selector();
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            dest_chain_selector,
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            true // is_enabled
        );

        // 31 is less than CCIP_LOCK_OR_BURN_V1_RET_BYTES
        let add_dest_bytes_overhead = 31;

        // This should fail with E_INVALID_DEST_BYTES_OVERHEAD
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            dest_chain_selector,
            vector[token_addr], // add_tokens
            vector[50u32], // add_min_fee_usd_cents
            vector[500u32], // add_max_fee_usd_cents
            vector[25u16], // add_deci_bps
            vector[5u32], // add_dest_gas_overhead
            vector[add_dest_bytes_overhead], // add_dest_bytes_overhead
            vector[true], // add_is_enabled
            vector[] // remove_tokens
        );
    }
}
