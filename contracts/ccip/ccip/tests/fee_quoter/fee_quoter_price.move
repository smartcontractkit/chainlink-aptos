#[test_only]
module ccip::fee_quoter_price {
    use std::object;
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;
    use ccip::client;

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_update_prices(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Update with new prices using helper
        let new_token_price: u256 = 2000; // Double the price
        let new_gas_price: u256 = 1000; // Set a non-zero gas price

        fee_quoter_setup::setup_prices(
            owner,
            token_addr,
            new_token_price,
            new_gas_price
        );

        // Verify the token price was updated
        let token_price = fee_quoter::get_token_price(token_addr);
        assert!(fee_quoter::timestamped_price_value(&token_price) == new_token_price);

        // Verify the gas price was updated
        let gas_price =
            fee_quoter::get_dest_chain_gas_price(
                fee_quoter_setup::get_dest_chain_selector()
            );
        assert!(fee_quoter::timestamped_price_value(&gas_price) == new_gas_price);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_convert_token_amount(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a second token with a different price
        let (_second_token_obj, second_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"second_token");

        // Add the second token as a fee token
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[], // fee_tokens_to_remove
            vector[second_token_addr] // fee_tokens_to_add
        );

        // Set prices: first token at 1000, second token at 2000
        fee_quoter::update_prices(
            owner,
            vector[token_addr, second_token_addr], // source_tokens
            vector[1000, 2000], // source_usd_per_token - second token is 2x the value
            vector[], // gas_dest_chain_selectors
            vector[] // gas_usd_per_unit_gas
        );

        // Convert 100 of token1 to token2 - should be 50 of token2 (since token2 is 2x the value)
        let converted_amount =
            fee_quoter::convert_token_amount(token_addr, 100, second_token_addr);
        assert!(converted_amount == 50);

        // Convert 100 of token2 to token1 - should be 200 of token1
        let converted_amount =
            fee_quoter::convert_token_amount(second_token_addr, 100, token_addr);
        assert!(converted_amount == 200);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_get_token_and_gas_prices(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Update token and gas prices
        let token_price: u256 = 2000;
        let gas_price: u256 = 1000;

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[token_price], // source_usd_per_token
            vector[fee_quoter_setup::get_dest_chain_selector()], // gas_dest_chain_selectors
            vector[gas_price] // gas_usd_per_unit_gas
        );

        // Get token and gas prices in a single call
        let (returned_token_price, returned_gas_price) =
            fee_quoter::get_token_and_gas_prices(
                token_addr, fee_quoter_setup::get_dest_chain_selector()
            );

        // Verify returned prices match what we set
        assert!(returned_token_price == token_price);
        assert!(returned_gas_price == gas_price);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_get_token_prices(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create multiple tokens
        let (_second_token_obj, second_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"second_token");
        let (_third_token_obj, third_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"third_token");

        // Add tokens to fee tokens list
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[], // fee_tokens_to_remove
            vector[second_token_addr, third_token_addr] // fee_tokens_to_add
        );

        // Set prices for all tokens
        fee_quoter::update_prices(
            owner,
            vector[token_addr, second_token_addr, third_token_addr], // source_tokens
            vector[1000, 2000, 3000], // source_usd_per_token - different prices
            vector[], // gas_dest_chain_selectors
            vector[] // gas_usd_per_unit_gas
        );

        // Get token prices for specific tokens
        let token_prices =
            fee_quoter::get_token_prices(vector[token_addr, third_token_addr]);

        // Verify we got the right prices in the right order
        assert!(token_prices.length() == 2);
        let first_price = fee_quoter::timestamped_price_value(&token_prices[0]);
        let second_price = fee_quoter::timestamped_price_value(&token_prices[1]);

        assert!(first_price == 1000); // First token price
        assert!(second_price == 3000); // Third token price
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_token_conversion_with_different_decimals(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create tokens with different decimals
        let constructor_ref =
            object::create_named_object(owner, b"token_with_more_decimals");

        std::primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            std::option::none(), // maximum supply
            std::string::utf8(b"token_with_more_decimals"), // name
            std::string::utf8(b"HIGH"), // symbol
            18, // 18 decimals - different from the default 0 in create_test_token
            std::string::utf8(b"http://www.example.com/favicon.ico"), // icon uri
            std::string::utf8(b"http://www.example.com") // project uri
        );

        let high_decimals_token =
            object::object_from_constructor_ref<std::fungible_asset::Metadata>(
                &constructor_ref
            );
        let high_decimals_token_addr = object::object_address(&high_decimals_token);

        // Add the new token as a fee token
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[], // fee_tokens_to_remove
            vector[high_decimals_token_addr] // fee_tokens_to_add
        );

        // Set prices for both tokens (standard token and high-decimal token)
        fee_quoter::update_prices(
            owner,
            vector[token_addr, high_decimals_token_addr], // source_tokens
            vector[1000000000000000000, 1000000000000000000], // same usd value per token (1 USD per token unit)
            vector[], // gas_dest_chain_selectors
            vector[] // gas_usd_per_unit_gas
        );

        // Now test conversion of amounts between tokens with different decimals
        // Since token_decimals aren't factored into the conversion, we should expect
        // the conversion to be based solely on the USD price ratios

        // Convert 1 token to high-decimal token
        let converted_amount =
            fee_quoter::convert_token_amount(token_addr, 1, high_decimals_token_addr);

        // Since 1 token = 1000 USD and 1 high-decimal token = 1000 USD
        // the conversion rate should be 1:1
        assert!(converted_amount == 1);

        // This test demonstrates that the token conversion logic in fee_quoter
        // is based on the token price ratio, regardless of token decimals
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65542, location = ccip::fee_quoter) // E_TOKEN_UPDATE_MISMATCH
    ]
    fun test_token_update_mismatch(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Mismatched array sizes (2 tokens but only 1 price)
        fee_quoter::update_prices(
            owner,
            vector[token_addr, fee_quoter_setup::get_mock_address_1()], // 2 tokens
            vector[1000u256], // Only 1 price
            vector[],
            vector[]
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65543, location = ccip::fee_quoter) // E_GAS_UPDATE_MISMATCH
    ]
    fun test_gas_update_mismatch(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Mismatched array sizes (2 chains but only 1 gas price)
        fee_quoter::update_prices(
            owner,
            vector[token_addr],
            vector[1000u256],
            vector[fee_quoter_setup::get_dest_chain_selector(), 12345u64], // 2 chains
            vector[1000u256] // Only 1 gas price
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65565, location = ccip::fee_quoter) // E_TO_TOKEN_AMOUNT_TOO_LARGE
    ]
    fun test_to_token_amount_too_large(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a second token with much lower price
        let (_second_token_obj, second_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"second_token");

        // Add the second token as a fee token
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[], // fee_tokens_to_remove
            vector[second_token_addr] // fee_tokens_to_add
        );

        // Set prices: first token at normal price, second token at very low price
        // This will make converting from first to second result in a very large amount
        fee_quoter::update_prices(
            owner,
            vector[token_addr, second_token_addr], // source_tokens
            vector[1000000000000000u256, 1u256], // Extreme price difference - second token is almost worthless
            vector[], // gas_dest_chain_selectors
            vector[] // gas_usd_per_unit_gas
        );

        // Convert a large amount of the valuable token to the cheap token
        // This should exceed u64::MAX and fail with E_TO_TOKEN_AMOUNT_TOO_LARGE
        let _ = fee_quoter::convert_token_amount(
            token_addr, 100000000, second_token_addr
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65550, location = ccip::fee_quoter) // E_UNSUPPORTED_NUMBER_OF_TOKENS
    ]
    fun test_unsupported_number_of_tokens(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a destination chain config with very limited token support
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(), // dest_chain_selector
            true, // is_enabled
            1, // max_number_of_tokens_per_msg - Only allows 1 token
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
            true, // enforce_out_of_order
            200, // default_token_fee_usd_cents
            30000, // default_token_dest_gas_overhead
            2000000, // default_tx_gas_limit
            3000000, // gas_multiplier_wei_per_eth
            20000000, // gas_price_staleness_threshold
            100 // network_fee_usd_cents
        );

        fee_quoter::update_prices(
            owner,
            vector[token_addr], // source_tokens
            vector[1000], // source_usd_per_token
            vector[fee_quoter_setup::get_dest_chain_selector()], // gas_dest_chain_selectors
            vector[1000] // gas_usd_per_unit_gas
        );

        // Create a second token
        let (_second_token_obj, second_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"second_token");

        // Try to send too many tokens for this chain config
        let receiver =
            x"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

        // This should fail with E_UNSUPPORTED_NUMBER_OF_TOKENS since we're trying to send 2 tokens
        // but the chain config only allows 1
        let _ =
            fee_quoter::get_validated_fee(
                fee_quoter_setup::get_dest_chain_selector(),
                receiver,
                b"test",
                vector[token_addr, second_token_addr], // 2 tokens but max is 1
                vector[100, 200], // token_amounts
                vector[@0x0, @0x0], // token_store_addresses
                token_addr, // fee_token
                @0x0, // fee_token_store
                client::encode_generic_extra_args_v2(500000, true) // extra args
            );
    }
}
