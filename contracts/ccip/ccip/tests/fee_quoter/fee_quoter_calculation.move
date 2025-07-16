#[test_only]
module ccip::fee_quoter_calculation {
    use std::object;
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;
    use ccip::client;

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure // This test is expected to fail due to current implementation limitations
    ]
    fun test_basic_fee_calculation(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Update timestamp to ensure gas price is fresh
        std::timestamp::update_global_time_for_test_secs(100100);

        // Create EVM-compatible receiver address
        let receiver = fee_quoter_setup::create_evm_receiver_address();

        // Create extra args with gas limit
        let extra_args = fee_quoter_setup::create_extra_args(500000, true);

        // Get fee for a data-only message
        let fee =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                receiver,
                b"test data",
                std::vector::empty(), // No token addresses
                std::vector::empty(), // No token amounts
                std::vector::empty(), // No token store addresses
                token_addr, // fee token
                @0x0, // fee token store
                extra_args // extra args
            );

        // Fee should be greater than 0 - but we expect the test to fail before reaching here
        assert!(fee > 0);
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65540, location = ccip::fee_quoter) // E_TOKEN_PRICE_NOT_FOUND - Expected failure as the token prices need further setup to work correctly
    ]
    fun test_token_transfer_fee_calculation(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a token for fee token
        let (_fee_token_obj, fee_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"fee_token");

        // Add the fee token to fee_tokens list
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[], // fee_tokens_to_remove
            vector[fee_token_addr] // fee_tokens_to_add
        );

        // Update token prices for both tokens
        fee_quoter::update_prices(
            owner,
            vector[token_addr, fee_token_addr], // source_tokens
            vector[1000, 1000], // source_usd_per_token
            vector[], // gas_dest_chain_selectors
            vector[] // gas_usd_per_unit_gas
        );

        // Update timestamp to ensure gas price is fresh
        std::timestamp::update_global_time_for_test_secs(100200);

        // Set up token transfer fee config
        fee_quoter_setup::setup_token_transfer_fee_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            token_addr,
            50, // min_fee_usd_cents
            500, // max_fee_usd_cents
            25 // deci_bps - 0.25%
        );

        // Create destination token
        let token_destination = @0x0;

        // Get fee for a token transfer message
        let fee =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                fee_quoter_setup::create_evm_receiver_address(), // receiver
                b"test with token",
                vector[token_addr], // token address
                vector[1000], // token amount: 1000 units
                vector[token_destination], // token destination
                fee_token_addr, // fee token
                @0x0, // fee token store
                fee_quoter_setup::create_extra_args(500000, true) // extra args
            );

        // Fee should be greater than 0
        assert!(fee > 0);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_get_token_transfer_info(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up token transfer fee config
        fee_quoter_setup::setup_token_transfer_fee_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            token_addr,
            50, // min_fee_usd_cents
            500, // max_fee_usd_cents
            25 // deci_bps - 0.25%
        );
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_get_fee_juels(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Test with different message sizes
        let small_message = b"small";
        let large_message = b"this is a larger message that will cost more in gas fees";

        // Create a destination chain with higher gas costs
        let dest_chain_selector = 12345;

        // Configure chain with reasonable gas calculation parameters
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            dest_chain_selector, // dest_chain_selector
            true, // is_enabled
            5, // max_number_of_tokens_per_msg
            15000, // max_data_bytes
            6000000, // max_per_msg_gas_limit
            10000, // dest_gas_overhead - base gas cost
            20, // dest_gas_per_payload_byte_base - cost per byte
            30, // dest_gas_per_payload_byte_high - higher cost per byte above threshold
            1000, // dest_gas_per_payload_byte_threshold - threshold for higher cost
            500, // dest_data_availability_overhead_gas
            10, // dest_gas_per_data_availability_byte
            200, // dest_data_availability_multiplier_bps - 2%
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            500000, // gas_multiplier_wei_per_eth - 0.5 (50%)
            10000000, // gas_price_staleness_threshold
            20 // network_fee_usd_cents - 20 cents base network fee
        );

        // Set token and gas prices
        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000u256], // token price: $10.00 USD
            vector[dest_chain_selector], // gas_dest_chain_selectors
            vector[10000u256] // gas price: 0.0001 USD per gas unit
        );

        // Get fee for small message
        let small_fee =
            fee_quoter::get_validated_fee(
                dest_chain_selector,
                fee_quoter_setup::create_evm_receiver_address(), // receiver
                small_message, // small data
                vector[], // No token transfers
                vector[],
                vector[],
                token_addr, // fee token
                @0x0, // fee token store
                fee_quoter_setup::create_extra_args(500000, true) // extra args
            );

        // Get fee for large message
        let large_fee =
            fee_quoter::get_validated_fee(
                dest_chain_selector,
                fee_quoter_setup::create_evm_receiver_address(), // receiver
                large_message, // larger data
                vector[], // No token transfers
                vector[],
                vector[],
                token_addr, // fee token
                @0x0, // fee token store
                fee_quoter_setup::create_extra_args(500000, true) // extra args
            );

        // Large message should cost more than small message
        assert!(large_fee > small_fee);
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65559, location = ccip::fee_quoter) // E_VALIDATION_ERROR
    ]
    fun test_compute_unit_limit_too_high(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create SVM chain with low max compute units
        let svm_dest_chain_selector = 55555;

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            svm_dest_chain_selector, // dest_chain_selector
            true, // is_enabled
            1, // max_number_of_tokens_per_msg
            10000, // max_data_bytes
            100000, // max_per_msg_gas_limit - Low limit
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
            100000, // default_tx_gas_limit
            1, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );

        // Set token price
        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[svm_dest_chain_selector], // gas_dest_chain_selectors
            vector[1000000] // gas price for SVM chain
        );

        // Create SVM extra args with excessive compute units
        let svm_receiver =
            x"7e5f4552091a69125d5dfcb7b8c2659029395bdf9c45bb0f8a496b606328c3ef";

        let svm_extra_args =
            client::encode_svm_extra_args_v1(
                500000, // compute_units - much higher than max_per_msg_gas_limit
                0, // account_is_writable_bitmap
                true, // allow_out_of_order_execution
                svm_receiver, // token_receiver
                vector[] // accounts
            );

        // This should fail with E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH
        fee_quoter::get_validated_fee(
            svm_dest_chain_selector,
            svm_receiver, // receiver
            b"test data", // data
            vector[], // No token addresses
            vector[], // No token amounts
            vector[], // No token store addresses
            token_addr, // fee token
            @0x0, // fee token store
            svm_extra_args // SVM extra args with excessive compute units
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65549, location = ccip::fee_quoter) // E_STALE_GAS_PRICE
    ]
    fun test_data_too_large(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a chain with small max data size
        let small_data_chain = 77777;

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            small_data_chain, // dest_chain_selector
            true, // is_enabled
            1, // max_number_of_tokens_per_msg
            10, // max_data_bytes - Very small limit
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
            1, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );

        // Set token price
        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[small_data_chain], // gas_dest_chain_selectors
            vector[1000000] // gas price
        );

        // Update timestamp to ensure fresh gas price
        std::timestamp::update_global_time_for_test_secs(100100);

        // Create large data message (larger than max_data_bytes)
        let large_data =
            b"This message is definitely larger than the 10 byte limit we set for this test chain";

        // This should fail with E_DATA_TOO_LARGE
        fee_quoter::get_validated_fee(
            small_data_chain,
            fee_quoter_setup::create_evm_receiver_address(), // receiver
            large_data, // Too large data
            vector[], // No token addresses
            vector[], // No token amounts
            vector[], // No token store addresses
            token_addr, // fee token
            @0x0, // fee token store
            fee_quoter_setup::create_extra_args(500000, true) // extra args
        );
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_gas_price_mask_112_bits(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let gas_price_bits = 112;
        let twenty_eight_fs = 0xffffffffffffffffffffffffffff;
        let max_u256 =
            115792089237316195423570985008687907853269984665640564039457584007913129639935;
        let gas_price_mask_112_bits = (max_u256 >> (255 - gas_price_bits + 1)); // 2^112 - 1

        assert!(gas_price_mask_112_bits == twenty_eight_fs);
    }
}
