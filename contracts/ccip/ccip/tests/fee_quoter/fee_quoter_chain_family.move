#[test_only]
module ccip::fee_quoter_chain_family {
    use std::object;
    use std::bcs;
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;
    use ccip::client;

    const LOCAL_8_TO_18_DECIMALS_LINK_MULTIPLIER: u256 = 10_000_000_000;

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_svm_chain_support(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create SVM chain config
        let svm_dest_chain_selector = 55555;

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            svm_dest_chain_selector, // dest_chain_selector
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
            fee_quoter_setup::get_chain_family_selector_svm(), // chain_family_selector - SVM for Solana
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
            vector[svm_dest_chain_selector], // gas_dest_chain_selectors
            vector[1000000] // gas price for SVM chain
        );

        // Create SVM-compatible receiver address (32 bytes)
        let svm_receiver =
            x"7e5f4552091a69125d5dfcb7b8c2659029395bdf9c45bb0f8a496b606328c3ef";

        // Create SVM extra args
        let compute_units = 200000;
        let account_is_writable_bitmap = 0;
        let allow_out_of_order_execution = true;
        let token_receiver =
            x"7e5f4552091a69125d5dfcb7b8c2659029395bdf9c45bb0f8a496b606328c3ef";
        let accounts = vector[];

        let svm_extra_args =
            client::encode_svm_extra_args_v1(
                compute_units,
                account_is_writable_bitmap,
                allow_out_of_order_execution,
                token_receiver,
                accounts
            );

        // Call get_validated_fee for SVM chain
        let fee =
            fee_quoter::get_validated_fee(
                svm_dest_chain_selector,
                svm_receiver, // receiver
                b"test data", // data
                vector[], // token addresses (empty for message-only)
                vector[], // token amounts
                vector[], // token store addresses
                token_addr, // fee token
                @0x0, // fee token store (not used in test)
                svm_extra_args // SVM extra args
            );

        assert!(fee > 0);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_aptos_chain_support(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create Aptos chain config
        let aptos_dest_chain_selector = 66666;

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            aptos_dest_chain_selector, // dest_chain_selector
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
            fee_quoter_setup::get_chain_family_selector_aptos(), // chain_family_selector - Aptos
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            1, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[aptos_dest_chain_selector], // gas_dest_chain_selectors
            vector[1000000] // gas price for Aptos chain
        );

        // Create Aptos-compatible receiver address (32 bytes)
        let aptos_receiver =
            @0xA7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8;

        // Create generic extra args
        let extra_args = fee_quoter_setup::create_extra_args(200000, true);

        // Call get_validated_fee for Aptos chain
        let fee =
            fee_quoter::get_validated_fee(
                aptos_dest_chain_selector,
                bcs::to_bytes(&aptos_receiver), // receiver
                b"test data", // data
                vector[], // token addresses (empty for message-only)
                vector[], // token amounts
                vector[], // token store addresses
                token_addr, // fee token
                @0x0, // fee token store (not used in test)
                extra_args // generic extra args
            );

        assert!(fee > 0);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_decode_svm_extra_args() {
        let svm_extra_args =
            client::encode_svm_extra_args_v1(
                200000, // compute_units
                0, // account_is_writable_bitmap
                true, // allow_out_of_order_execution
                bcs::to_bytes(&fee_quoter_setup::get_mock_address_4()), // token_receiver
                vector[] // accounts
            );

        let (
            compute_units,
            account_is_writable_bitmap,
            allow_out_of_order_execution,
            token_receiver,
            accounts
        ) = fee_quoter::test_decode_svm_extra_args(svm_extra_args);

        assert!(compute_units == 200000);
        assert!(account_is_writable_bitmap == 0);
        assert!(allow_out_of_order_execution == true);
        assert!(
            token_receiver == bcs::to_bytes(&fee_quoter_setup::get_mock_address_4())
        );
        assert!(accounts == vector[]);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_process_svm_message_args(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);
        let dest_chain_selector = 100;

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            dest_chain_selector, // dest_chain_selector
            true, // is_enabled
            1000, // max_number_of_tokens_per_msg
            20000, // max_data_bytes
            5000000, // max_per_msg_gas_limit
            100000, // dest_gas_overhead
            100, // dest_gas_per_payload_byte_base
            200, // dest_gas_per_payload_byte_high
            300, // dest_gas_per_payload_byte_threshold
            400000, // dest_data_availability_overhead_gas
            500, // dest_gas_per_data_availability_byte
            600, // dest_data_availability_multiplier_bps
            fee_quoter_setup::get_chain_family_selector_svm(), // chain_family_selector
            true, // enforce_out_of_order
            1000, // default_token_fee_usd_cents
            2000, // default_token_dest_gas_overhead
            3000000, // default_tx_gas_limit
            4000000, // gas_multiplier_wei_per_eth
            5000000, // gas_price_staleness_threshold
            6000000 // network_fee_usd_cents
        );

        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            dest_chain_selector, // dest_chain_selector
            vector[token_addr, fee_quoter_setup::get_mock_address_4()], // add_tokens
            vector[100, 200], // add_min_fee_usd_cents
            vector[3000, 4000], // add_max_fee_usd_cents
            vector[500, 600], // add_deci_bps
            vector[700, 800], // add_dest_gas_overhead
            vector[900, 1000], // add_dest_bytes_overhead
            vector[true, false], // add_is_enabled
            vector[] // remove_tokens
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr, fee_quoter_setup::get_mock_address_4()], // source_tokens
            vector[100, 200], // source_usd_per_token
            vector[dest_chain_selector, dest_chain_selector], // gas_dest_chain_selectors
            vector[1000, 2000] // gas_usd_per_unit_gas
        );

        let svm_extra_args =
            client::encode_svm_extra_args_v1(
                200000, // compute_units
                0, // account_is_writable_bitmap
                true, // allow_out_of_order_execution
                bcs::to_bytes(&fee_quoter_setup::get_mock_address_4()), // token_receiver
                vector[] // accounts
            );
        let (
            msg_fee_juels,
            is_out_of_order_execution,
            converted_extra_args,
            dest_exec_data_per_token
        ) =
            fee_quoter::process_message_args(
                dest_chain_selector,
                token_addr,
                1000, // fee_token_amount
                svm_extra_args, // extra_args
                vector[token_addr], // local_token_addresses,
                vector[bcs::to_bytes(&fee_quoter_setup::get_mock_address_4())], // dest_token_addresses
                vector[bcs::to_bytes(&fee_quoter_setup::get_mock_address_3())] // dest_pool_datas
            );

        assert!(
            msg_fee_juels == 1000 * LOCAL_8_TO_18_DECIMALS_LINK_MULTIPLIER
        );
        assert!(is_out_of_order_execution == true);
        assert!(converted_extra_args == svm_extra_args);
        assert!(dest_exec_data_per_token == vector[x"bc020000"]);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_generic_extra_args_v2_encoding(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, _token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);

        // Test the extra args encoder function with various parameters
        let gas_limit = 500000;
        let strict_mode = true;

        let extra_args = client::encode_generic_extra_args_v2(gas_limit, strict_mode);

        // Verify the encoding contains the tag and values
        // Generic extra args v2 tag is: 0x181dcf10
        // We can't directly access the encoded values, but we can verify it's not empty
        // and starts with the correct tag
        assert!(extra_args.length() > 0);

        // Tag should be the first 4 bytes
        assert!(extra_args[0] == 0x18);
        assert!(extra_args[1] == 0x1d);
        assert!(extra_args[2] == 0xcf);
        assert!(extra_args[3] == 0x10);

        // Verify strict mode = false works too
        let non_strict_args = client::encode_generic_extra_args_v2(gas_limit, false);
        assert!(non_strict_args.length() > 0);

        // The first 4 bytes (tag) should be the same
        assert!(non_strict_args[0] == 0x18);
        assert!(non_strict_args[1] == 0x1d);
        assert!(non_strict_args[2] == 0xcf);
        assert!(non_strict_args[3] == 0x10);

        // But the contents should be different due to strict mode change
        // (exact byte comparison would require inspecting abi encoding details)
        let match = true;
        let i = 0;
        while (i < extra_args.length() && i < non_strict_args.length()) {
            if (i >= 4 && extra_args[i] != non_strict_args[i]) {
                match = false;
                break
            };
            i = i + 1;
        };

        // There should be at least one byte difference in the encoding
        assert!(!match);
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65564, location = ccip::fee_quoter) // E_UNKNOWN_CHAIN_FAMILY_SELECTOR
    ]
    fun test_unknown_chain_family_selector(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, _token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);

        // Create a new chain with an unsupported chain family selector
        let test_chain_selector = 99999;
        let invalid_chain_family = x"12345678"; // Not a supported chain family

        // Configure the chain with an invalid chain family
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            test_chain_selector, // dest_chain_selector
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
            invalid_chain_family, // invalid chain family selector
            false, // enforce_out_of_order
            0, // default_token_fee_usd_cents
            0, // default_token_dest_gas_overhead
            1000000, // default_tx_gas_limit
            1, // gas_multiplier_wei_per_eth
            10000000, // gas_price_staleness_threshold
            0 // network_fee_usd_cents
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65556, location = ccip::fee_quoter) // E_INVALID_EXTRA_ARGS_TAG
    ]
    fun test_invalid_extra_args_tag(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up destination chain config
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            fee_quoter_setup::get_chain_family_selector_evm(),
            true
        );

        // Set up token prices
        fee_quoter_setup::setup_prices(
            owner,
            token_addr,
            1000, // token price
            1000 // gas price
        );

        // Set up token transfer fee config
        fee_quoter_setup::setup_token_transfer_fee_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            token_addr,
            50, // min_fee_usd_cents
            500, // max_fee_usd_cents
            25 // deci_bps
        );

        let receiver = fee_quoter_setup::create_evm_receiver_address();

        // Create invalid extra args with wrong tag
        let invalid_tag = x"00000000"; // Not a valid tag value

        // This should fail with E_INVALID_EXTRA_ARGS_TAG
        let _ =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                receiver,
                b"test",
                vector[], // token_addresses
                vector[], // token_amounts
                vector[], // token_store_addresses
                token_addr, // fee_token
                @0x0, // fee_token_store
                invalid_tag
            );
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_out_of_order_execution_required(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up destination chain config
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            true, // is_enabled
            5, // max_number_of_tokens_per_msg
            15000, // max_data_bytes
            6000000, // max_per_msg_gas_limit
            10000, // dest_gas_overhead
            20, // dest_gas_per_payload_byte_base
            30, // dest_gas_per_payload_byte_high
            2000, // dest_gas_per_payload_byte_threshold
            50000, // dest_data_availability_overhead_gas
            60, // dest_gas_per_data_availability_byte
            1000, // dest_data_availability_multiplier_bps
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector
            true, // enforce_out_of_order (unused; OOO is always true)
            200, // default_token_fee_usd_cents
            30000, // default_token_dest_gas_overhead
            2000000, // default_tx_gas_limit
            3000000, // gas_multiplier_wei_per_eth
            20000000, // gas_price_staleness_threshold
            100 // network_fee_usd_cents
        );

        fee_quoter_setup::setup_prices(
            owner,
            token_addr,
            1000, // token price
            1000 // gas price
        );

        let receiver = fee_quoter_setup::create_evm_receiver_address();

        // Extra args with allow_out_of_order_execution = false; contract ignores and overrides to true
        let extra_args = fee_quoter_setup::create_extra_args(500000, false);

        // Should succeed: we no longer revert on user's OOO value; we ignore and always use true
        let _fee =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                receiver,
                b"test",
                vector[], // token_addresses
                vector[], // token_amounts
                vector[], // token_store_addresses
                token_addr, // fee_token
                @0x0, // fee_token_store
                extra_args
            );

        // Verify process_message_args returns is_out_of_order_execution == true regardless of user input
        let (
            _msg_fee_juels,
            is_out_of_order_execution,
            _converted_extra_args,
            _dest_exec_data_per_token
        ) =
            fee_quoter::process_message_args(
                fee_quoter_setup::get_dest_chain_selector(),
                token_addr,
                1000, // fee_token_amount
                extra_args,
                vector[],
                vector[],
                vector[]
            );
        assert!(is_out_of_order_execution, 0);
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65551, location = ccip::fee_quoter) // E_INVALID_EVM_ADDRESS
    ]
    fun test_invalid_evm_address(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up destination chain config with proper options
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            fee_quoter_setup::get_chain_family_selector_evm(),
            true
        );

        // Set up token prices
        fee_quoter_setup::setup_prices(
            owner,
            token_addr,
            1000, // token price
            1000 // gas price
        );

        // Set up token transfer fee config
        fee_quoter_setup::setup_token_transfer_fee_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            token_addr,
            50, // min_fee_usd_cents
            500, // max_fee_usd_cents
            25 // deci_bps
        );

        // Create an invalid EVM address (not the right length)
        let invalid_evm_addr = x"abcd"; // Too short for EVM

        // This should fail with E_INVALID_EVM_ADDRESS
        let _ =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                invalid_evm_addr, // receiver
                b"test",
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
        expected_failure(abort_code = 65572, location = ccip::fee_quoter) // E_INVALID_SVM_RECEIVER_LENGTH
    ]
    fun test_invalid_svm_address(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set up destination chain config with SVM family selector
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            fee_quoter_setup::get_chain_family_selector_svm(),
            true
        );

        fee_quoter_setup::setup_prices(
            owner,
            token_addr,
            1000, // token price
            1000 // gas price
        );

        fee_quoter_setup::setup_token_transfer_fee_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            token_addr,
            50, // min_fee_usd_cents
            500, // max_fee_usd_cents
            25 // deci_bps
        );

        // Create an invalid SVM address (not the right length)
        let invalid_svm_addr = x"0102030405060708090a0b0c0d0e0f"; // Too short for SVM

        // This should fail with E_INVALID_SVM_RECEIVER_LENGTH
        let _ =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                invalid_svm_addr,
                b"test",
                vector[], // token addresses
                vector[], // token amounts
                vector[], // token store addresses
                token_addr, // fee token
                @0x0, // fee token store
                client::encode_svm_extra_args_v1(
                    500000,
                    0,
                    true,
                    x"0000000000000000000000000000000000000000000000000000000000000001",
                    vector[
                        x"0000000000000000000000000000000000000000000000000000000000000002"
                    ]
                )
            );
    }
}
