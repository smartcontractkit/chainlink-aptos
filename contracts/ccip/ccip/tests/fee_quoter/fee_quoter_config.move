#[test_only]
module ccip::fee_quoter_config {
    use std::object;
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_apply_dest_chain_config_updates(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, _token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let dest_chain_selector = fee_quoter_setup::get_dest_chain_selector();
        let _initial_config = fee_quoter::get_dest_chain_config(dest_chain_selector);

        fee_quoter::apply_dest_chain_config_updates(
            owner,
            dest_chain_selector, // dest_chain_selector
            true, // is_enabled
            2, // max_number_of_tokens_per_msg (changed from 1)
            20000, // max_data_bytes (changed from 10000)
            8000000, // max_per_msg_gas_limit (changed from 7000000)
            1000, // dest_gas_overhead (changed from 0)
            10, // dest_gas_per_payload_byte_base (changed from 0)
            20, // dest_gas_per_payload_byte_high (changed from 0)
            1000, // dest_gas_per_payload_byte_threshold (changed from 0)
            2000, // dest_data_availability_overhead_gas (changed from 0)
            10, // dest_gas_per_data_availability_byte (changed from 0)
            500, // dest_data_availability_multiplier_bps (changed from 0)
            fee_quoter_setup::get_chain_family_selector_evm(), // chain_family_selector (same)
            true, // enforce_out_of_order (changed from false)
            100, // default_token_fee_usd_cents (changed from 0)
            500, // default_token_dest_gas_overhead (changed from 0)
            1000000, // default_tx_gas_limit (same)
            500000, // gas_multiplier_wei_per_eth (changed from 0)
            10000000, // gas_price_staleness_threshold (same)
            50 // network_fee_usd_cents (changed from 0)
        );

        // Get the updated configuration
        let updated_config = fee_quoter::get_dest_chain_config(dest_chain_selector);

        let (
            is_enabled,
            max_number_of_tokens_per_msg,
            max_data_bytes,
            max_per_msg_gas_limit,
            dest_gas_overhead,
            dest_gas_per_payload_byte_base,
            dest_gas_per_payload_byte_high,
            dest_gas_per_payload_byte_threshold,
            dest_data_availability_overhead_gas,
            dest_gas_per_data_availability_byte,
            dest_data_availability_multiplier_bps,
            chain_family_selector,
            enforce_out_of_order,
            default_token_fee_usd_cents,
            default_token_dest_gas_overhead,
            default_tx_gas_limit,
            gas_multiplier_wei_per_eth,
            gas_price_staleness_threshold,
            network_fee_usd_cents
        ) = fee_quoter::dest_chain_config_values(updated_config);

        assert!(is_enabled == true);
        assert!(max_number_of_tokens_per_msg == 2);
        assert!(max_data_bytes == 20000);
        assert!(max_per_msg_gas_limit == 8000000);
        assert!(dest_gas_overhead == 1000);
        assert!(dest_gas_per_payload_byte_base == 10);
        assert!(dest_gas_per_payload_byte_high == 20);
        assert!(dest_gas_per_payload_byte_threshold == 1000);
        assert!(dest_data_availability_overhead_gas == 2000);
        assert!(dest_gas_per_data_availability_byte == 10);
        assert!(dest_data_availability_multiplier_bps == 500);
        assert!(
            chain_family_selector == fee_quoter_setup::get_chain_family_selector_evm()
        );
        assert!(enforce_out_of_order == true);
        assert!(default_token_fee_usd_cents == 100);
        assert!(default_token_dest_gas_overhead == 500);
        assert!(default_tx_gas_limit == 1000000);
        assert!(gas_multiplier_wei_per_eth == 500000);
        assert!(gas_price_staleness_threshold == 10000000);
        assert!(network_fee_usd_cents == 50);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_apply_token_transfer_fee_config_updates(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a second token
        let (_second_token_obj, second_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"second_token");

        // Update token transfer fee config for the new token
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(), // dest_chain_selector
            vector[second_token_addr], // add_tokens
            vector[50], // add_min_fee_usd_cents
            vector[500], // add_max_fee_usd_cents
            vector[10], // add_deci_bps - 0.01% (1 bps)
            vector[5000], // add_dest_gas_overhead
            vector[64], // add_dest_bytes_overhead
            vector[true], // add_is_enabled
            vector[] // remove_tokens
        );

        // Get and verify the new config
        let config =
            fee_quoter::get_token_transfer_fee_config(
                fee_quoter_setup::get_dest_chain_selector(), second_token_addr
            );
        let (
            min_fee_usd_cents,
            max_fee_usd_cents,
            deci_bps,
            dest_gas_overhead,
            dest_bytes_overhead,
            is_enabled
        ) = fee_quoter::token_transfer_fee_config_values(config);
        assert!(min_fee_usd_cents == 50);
        assert!(max_fee_usd_cents == 500);
        assert!(deci_bps == 10);
        assert!(dest_gas_overhead == 5000);
        assert!(dest_bytes_overhead == 64);
        assert!(is_enabled == true);

        // Now update by removing the original token's config
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(), // dest_chain_selector
            vector[], // add_tokens
            vector[], // add_min_fee_usd_cents
            vector[], // add_max_fee_usd_cents
            vector[], // add_deci_bps
            vector[], // add_dest_gas_overhead
            vector[], // add_dest_bytes_overhead
            vector[], // add_is_enabled
            vector[token_addr] // remove_tokens
        );

        // Check that the second token's config is still there
        let config =
            fee_quoter::get_token_transfer_fee_config(
                fee_quoter_setup::get_dest_chain_selector(), second_token_addr
            );
        let (
            min_fee_usd_cents,
            _max_fee_usd_cents,
            _deci_bps,
            _dest_gas_overhead,
            _dest_bytes_overhead,
            _is_enabled
        ) = fee_quoter::token_transfer_fee_config_values(config);
        assert!(min_fee_usd_cents == 50);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_removed_fee_config_reverts(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // First, verify we can access the token's fee config after setup
        let _initial_config =
            fee_quoter::get_token_transfer_fee_config(
                fee_quoter_setup::get_dest_chain_selector(), token_addr
            );

        // Now remove the token's fee config
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(), // dest_chain_selector
            vector[], // add_tokens
            vector[], // add_min_fee_usd_cents
            vector[], // add_max_fee_usd_cents
            vector[], // add_deci_bps
            vector[], // add_dest_gas_overhead
            vector[], // add_dest_bytes_overhead
            vector[], // add_is_enabled
            vector[token_addr] // remove_tokens
        );

        // Attempt to access the removed config
        // This should return an empty config with default values
        let default_config =
            fee_quoter::get_token_transfer_fee_config(
                fee_quoter_setup::get_dest_chain_selector(), token_addr
            );
        let (
            default_min_fee_usd_cents,
            default_max_fee_usd_cents,
            default_deci_bps,
            default_dest_gas_overhead,
            default_dest_bytes_overhead,
            default_is_enabled
        ) = fee_quoter::token_transfer_fee_config_values(default_config);

        assert!(default_min_fee_usd_cents == 0);
        assert!(default_max_fee_usd_cents == 0);
        assert!(default_deci_bps == 0);
        assert!(default_dest_gas_overhead == 0);
        assert!(default_dest_bytes_overhead == 0);
        assert!(default_is_enabled == false);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_token_transfer_fee_config_values(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Set custom token transfer fee config values
        let min_fee_usd_cents: u32 = 50;
        let max_fee_usd_cents: u32 = 500;
        let deci_bps: u16 = 25; // 0.25%
        let dest_gas_overhead: u32 = 10000;
        let dest_bytes_overhead: u32 = 128;
        let is_enabled: bool = true;

        // Update the token transfer fee config
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(), // dest_chain_selector
            vector[token_addr], // add_tokens
            vector[min_fee_usd_cents], // add_min_fee_usd_cents
            vector[max_fee_usd_cents], // add_max_fee_usd_cents
            vector[deci_bps], // add_deci_bps
            vector[dest_gas_overhead], // add_dest_gas_overhead
            vector[dest_bytes_overhead], // add_dest_bytes_overhead
            vector[is_enabled], // add_is_enabled
            vector[] // remove_tokens
        );

        // Get the updated config
        let config =
            fee_quoter::get_token_transfer_fee_config(
                fee_quoter_setup::get_dest_chain_selector(), token_addr
            );

        // Call the token_transfer_fee_config_values function
        let (
            returned_min_fee,
            returned_max_fee,
            returned_deci_bps,
            returned_gas_overhead,
            returned_bytes_overhead,
            returned_is_enabled
        ) = fee_quoter::token_transfer_fee_config_values(config);

        // Verify the values match what we set
        assert!(returned_min_fee == min_fee_usd_cents);
        assert!(returned_max_fee == max_fee_usd_cents);
        assert!(returned_deci_bps == deci_bps);
        assert!(returned_gas_overhead == dest_gas_overhead);
        assert!(returned_bytes_overhead == dest_bytes_overhead);
        assert!(returned_is_enabled == is_enabled);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_dest_chain_config_values(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, _token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);

        // Create custom dest chain config using helper
        fee_quoter_setup::setup_dest_chain_config(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            fee_quoter_setup::get_chain_family_selector_evm(),
            true
        );

        // Get the updated config
        let config =
            fee_quoter::get_dest_chain_config(fee_quoter_setup::get_dest_chain_selector());

        // Call the dest_chain_config_values function
        let (
            is_enabled,
            max_number_of_tokens_per_msg,
            max_data_bytes,
            max_per_msg_gas_limit,
            dest_gas_overhead,
            dest_gas_per_payload_byte_base,
            dest_gas_per_payload_byte_high,
            dest_gas_per_payload_byte_threshold,
            dest_data_availability_overhead_gas,
            dest_gas_per_data_availability_byte,
            dest_data_availability_multiplier_bps,
            chain_family_selector,
            enforce_out_of_order,
            default_token_fee_usd_cents,
            default_token_dest_gas_overhead,
            default_tx_gas_limit,
            gas_multiplier_wei_per_eth,
            gas_price_staleness_threshold,
            network_fee_usd_cents
        ) = fee_quoter::dest_chain_config_values(config);

        // Verify the values match what we set
        assert!(is_enabled == true);
        assert!(max_number_of_tokens_per_msg == 5);
        assert!(max_data_bytes == 15000);
        assert!(max_per_msg_gas_limit == 6000000);
        assert!(dest_gas_overhead == 10000);
        assert!(dest_gas_per_payload_byte_base == 20);
        assert!(dest_gas_per_payload_byte_high == 30);
        assert!(dest_gas_per_payload_byte_threshold == 2000);
        assert!(dest_data_availability_overhead_gas == 50000);
        assert!(dest_gas_per_data_availability_byte == 60);
        assert!(dest_data_availability_multiplier_bps == 1000);
        assert!(
            chain_family_selector == fee_quoter_setup::get_chain_family_selector_evm()
        );
        assert!(enforce_out_of_order == true);
        assert!(default_token_fee_usd_cents == 200);
        assert!(default_token_dest_gas_overhead == 30000);
        assert!(default_tx_gas_limit == 2000000);
        assert!(gas_multiplier_wei_per_eth == 3000000);
        assert!(gas_price_staleness_threshold == 20000000);
        assert!(network_fee_usd_cents == 100);
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65544, location = ccip::fee_quoter) // E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH
    ]
    fun test_token_transfer_fee_config_mismatch(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a token transfer fee config update with mismatched array sizes
        fee_quoter::apply_token_transfer_fee_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(),
            vector[token_addr, fee_quoter_setup::get_mock_address_1()], // 2 tokens
            vector[50u32], // Only 1 min fee
            vector[500u32, 600u32], // 2 max fees
            vector[25u16], // Only 1 deci_bps
            vector[10000u32], // Only 1 gas overhead
            vector[128u32], // Only 1 bytes overhead
            vector[true], // Only 1 is_enabled
            vector[] // remove_tokens
        );
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65563, location = ccip::fee_quoter) // E_INVALID_GAS_LIMIT
    ]
    fun test_invalid_gas_limit(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, _token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);

        // Try to create a chain config with default_tx_gas_limit = 0
        fee_quoter::apply_dest_chain_config_updates(
            owner,
            fee_quoter_setup::get_dest_chain_selector(), // dest_chain_selector
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
            true, // enforce_out_of_order
            200, // default_token_fee_usd_cents
            30000, // default_token_dest_gas_overhead
            0, // default_tx_gas_limit - INVALID: cannot be zero
            3000000, // gas_multiplier_wei_per_eth
            20000000, // gas_price_staleness_threshold
            100 // network_fee_usd_cents
        );
    }
}
