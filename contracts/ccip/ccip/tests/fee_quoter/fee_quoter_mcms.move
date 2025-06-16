#[test_only]
module ccip::fee_quoter_mcms {

    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;
    use ccip::auth;
    use std::account;
    use std::string;
    use std::vector;
    use std::signer;
    use mcms::mcms_registry;
    use mcms::mcms_account;

    const DEST_CHAIN_SELECTOR: u64 = 5678;
    const CHAIN_FAMILY_SELECTOR_EVM: vector<u8> = x"2812d52c";

    fun setup_mcms(mcms: &signer, ccip: &signer) {
        account::create_account_for_test(signer::address_of(mcms));
        mcms_registry::init_module_for_testing(mcms);
        mcms_account::init_module_for_testing(mcms);

        auth::test_register_mcms_entrypoint(ccip);
        fee_quoter::test_register_mcms_entrypoint(ccip);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    /// Test the mcms entrypoint dispatch functionality
    /// MCMS signer generated must be registered as a CCIP offramp
    fun test_mcms_entrypoint_dispatch_functionality(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = std::object::object_address(&token_obj);
        setup_mcms(owner, ccip);

        let preexisting_owner_address =
            mcms_registry::get_preexisting_code_object_owner_address(
                signer::address_of(ccip)
            );
        // set MCMS signer as CCIP offramp
        auth::apply_allowed_offramp_updates(
            owner,
            vector[], // offramps_to_remove
            vector[preexisting_owner_address] // offramps_to_add
        );

        transfer_ccip_ownership(owner, ccip);

        let data = vector[];
        vector::append(
            &mut data,
            std::bcs::to_bytes(&vector<address>[])
        ); // fee_tokens_to_remove
        vector::append(&mut data, std::bcs::to_bytes(&vector[token_addr])); // fee_tokens_to_add

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip,
                string::utf8(b"fee_quoter"),
                string::utf8(b"apply_fee_token_updates"),
                data
            );
        fee_quoter::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@ccip);

        // Verify the fee_tokens_to_add was added
        let fee_tokens = fee_quoter::get_fee_tokens();
        assert!(fee_tokens.contains(&token_addr));

        // ============ fee_quoter::apply_token_transfer_fee_config_updates ============

        let data = vector[];
        vector::append(&mut data, std::bcs::to_bytes(&DEST_CHAIN_SELECTOR)); // dest_chain_selector
        vector::append(&mut data, std::bcs::to_bytes(&vector[token_addr])); // add_tokens
        vector::append(&mut data, std::bcs::to_bytes(&vector[1 as u32])); // add_min_fee_usd_cents
        vector::append(&mut data, std::bcs::to_bytes(&vector[12 as u32])); // add_max_fee_usd_cents
        vector::append(&mut data, std::bcs::to_bytes(&vector[0 as u16])); // add_deci_bps
        vector::append(&mut data, std::bcs::to_bytes(&vector[33 as u32])); // add_dest_gas_overhead
        vector::append(&mut data, std::bcs::to_bytes(&vector[33 as u32])); // add_dest_bytes_overhead
        vector::append(&mut data, std::bcs::to_bytes(&vector[true])); // add_is_enabled
        vector::append(
            &mut data,
            std::bcs::to_bytes(&vector<address>[])
        ); // remove_tokens

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip,
                string::utf8(b"fee_quoter"),
                string::utf8(b"apply_token_transfer_fee_config_updates"),
                data
            );
        fee_quoter::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@ccip);

        // Verify the fee_token_transfer_fee_config_updates was added
        let fee_token_transfer_fee_config =
            fee_quoter::get_token_transfer_fee_config(DEST_CHAIN_SELECTOR, token_addr);
        let (
            min_fee_usd_cents,
            max_fee_usd_cents,
            deci_bps,
            dest_gas_overhead,
            dest_bytes_overhead,
            is_enabled
        ) = fee_quoter::token_transfer_fee_config_values(fee_token_transfer_fee_config);
        assert!(min_fee_usd_cents == 1);
        assert!(max_fee_usd_cents == 12);
        assert!(deci_bps == 0);
        assert!(dest_gas_overhead == 33);
        assert!(dest_bytes_overhead == 33);
        assert!(is_enabled == true);

        // ============ fee_quoter::update_prices ============

        let data = vector[];
        vector::append(&mut data, std::bcs::to_bytes(&vector[token_addr])); // source_tokens
        vector::append(&mut data, std::bcs::to_bytes(&vector[1000 as u256])); // source_usd_per_token
        vector::append(&mut data, std::bcs::to_bytes(&vector[DEST_CHAIN_SELECTOR])); // gas_dest_chain_selectors
        vector::append(&mut data, std::bcs::to_bytes(&vector[0 as u256])); // gas_usd_per_unit_gas

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip,
                string::utf8(b"fee_quoter"),
                string::utf8(b"update_prices"),
                data
            );
        fee_quoter::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@ccip);

        // Verify the prices were updated
        let token_price = fee_quoter::get_token_price(token_addr);
        assert!(fee_quoter::timestamped_price_value(&token_price) == 1000);

        // ============ fee_quoter::apply_premium_multiplier_wei_per_eth_updates ============

        let data = vector[];
        vector::append(&mut data, std::bcs::to_bytes(&vector[token_addr])); // tokens
        vector::append(&mut data, std::bcs::to_bytes(&vector[150 as u64])); // premium_multiplier_wei_per_eth

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip,
                string::utf8(b"fee_quoter"),
                string::utf8(b"apply_premium_multiplier_wei_per_eth_updates"),
                data
            );
        fee_quoter::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@ccip);

        // Verify the premium_multiplier_wei_per_eth was updated
        let premium_multiplier_wei_per_eth =
            fee_quoter::get_premium_multiplier_wei_per_eth(token_addr);
        assert!(premium_multiplier_wei_per_eth == 150);

        // ============ fee_quoter::apply_dest_chain_config_updates ============

        let data = vector[];
        vector::append(&mut data, std::bcs::to_bytes(&DEST_CHAIN_SELECTOR)); // dest_chain_selector
        vector::append(&mut data, std::bcs::to_bytes(&true)); // is_enabled
        vector::append(&mut data, std::bcs::to_bytes(&(100 as u16))); // max_number_of_tokens_per_msg
        vector::append(&mut data, std::bcs::to_bytes(&(1000 as u32))); // max_data_bytes
        vector::append(&mut data, std::bcs::to_bytes(&(1000000 as u32))); // max_per_msg_gas_limit
        vector::append(&mut data, std::bcs::to_bytes(&(100 as u32))); // dest_gas_overhead
        vector::append(&mut data, std::bcs::to_bytes(&(1 as u8))); // dest_gas_per_payload_byte_base
        vector::append(&mut data, std::bcs::to_bytes(&(1 as u8))); // dest_gas_per_payload_byte_high
        vector::append(&mut data, std::bcs::to_bytes(&(100 as u16))); // dest_gas_per_payload_byte_threshold
        vector::append(&mut data, std::bcs::to_bytes(&(1000 as u32))); // dest_data_availability_overhead_gas
        vector::append(&mut data, std::bcs::to_bytes(&(100 as u16))); // dest_gas_per_data_availability_byte
        vector::append(&mut data, std::bcs::to_bytes(&(100 as u16))); // dest_data_availability_multiplier_bps
        vector::append(&mut data, std::bcs::to_bytes(&CHAIN_FAMILY_SELECTOR_EVM)); // chain_family_selector
        vector::append(&mut data, std::bcs::to_bytes(&false)); // enforce_out_of_order
        vector::append(&mut data, std::bcs::to_bytes(&(0 as u16))); // default_token_fee_usd_cents
        vector::append(&mut data, std::bcs::to_bytes(&(0 as u32))); // default_token_dest_gas_overhead
        vector::append(&mut data, std::bcs::to_bytes(&(1000000 as u32))); // default_tx_gas_limit
        vector::append(&mut data, std::bcs::to_bytes(&(1 as u64))); // gas_multiplier_wei_per_eth
        vector::append(&mut data, std::bcs::to_bytes(&(1000000 as u32))); // gas_price_staleness_threshold
        vector::append(&mut data, std::bcs::to_bytes(&(0 as u32))); // network_fee_usd_cents

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip,
                string::utf8(b"fee_quoter"),
                string::utf8(b"apply_dest_chain_config_updates"),
                data
            );
        fee_quoter::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@ccip);

        let dest_chain_config = fee_quoter::get_dest_chain_config(DEST_CHAIN_SELECTOR);
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
        ) = fee_quoter::dest_chain_config_values(dest_chain_config);
        assert!(is_enabled == true);
        assert!(max_number_of_tokens_per_msg == 100);
        assert!(max_data_bytes == 1000);
        assert!(max_per_msg_gas_limit == 1000000);
        assert!(dest_gas_overhead == 100);
        assert!(dest_gas_per_payload_byte_base == 1);
        assert!(dest_gas_per_payload_byte_high == 1);
        assert!(dest_gas_per_payload_byte_threshold == 100);
        assert!(dest_data_availability_overhead_gas == 1000);
        assert!(dest_gas_per_data_availability_byte == 100);
        assert!(dest_data_availability_multiplier_bps == 100);
        assert!(chain_family_selector == CHAIN_FAMILY_SELECTOR_EVM);
        assert!(enforce_out_of_order == false);
        assert!(default_token_fee_usd_cents == 0);
        assert!(default_token_dest_gas_overhead == 0);
        assert!(default_tx_gas_limit == 1000000);
        assert!(gas_multiplier_wei_per_eth == 1);
        assert!(gas_price_staleness_threshold == 1000000);
        assert!(network_fee_usd_cents == 0);

    }

    fun transfer_ccip_ownership(owner: &signer, ccip: &signer) {
        let preexisting_owner_address =
            mcms_registry::get_preexisting_code_object_owner_address(
                signer::address_of(ccip)
            );
        auth::transfer_ownership(owner, preexisting_owner_address);

        let metadata =
            mcms_registry::test_start_dispatch(
                @ccip,
                string::utf8(b"auth"),
                string::utf8(b"accept_ownership"),
                vector[]
            );
        auth::mcms_entrypoint(metadata);
        mcms_registry::test_finish_dispatch(@ccip);

        auth::execute_ownership_transfer(owner, preexisting_owner_address);
    }
}
