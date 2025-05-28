#[test_only]
module ccip::fee_quoter_view {
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;
    use std::object;
    use ccip::client;

    // Link has 8 decimals on Aptos and 18 decimals on it's native chain, Ethereum. We want to emit
    // the fee in juels (1e18) denomination for consistency across chains. This means we multiply
    // the fee by 1e8 on Aptos before we emit it in the event.
    const LOCAL_8_TO_18_DECIMALS_LINK_MULTIPLIER: u256 = 10_000_000_000;

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_process_message_args(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        let fee_token_amount = 1000;

        let extra_args = client::encode_generic_extra_args_v2(500000, true); // 500k gas limit with OOO

        let dest_token_address =
            x"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

        // Create pool data (simplified for test)
        let dest_pool_data =
            x"0000000000000000000000000000000000000000000000000000000000000000";

        let (
            msg_fee_juels,
            is_out_of_order_execution,
            converted_extra_args,
            dest_exec_data_per_token
        ) =
            fee_quoter::process_message_args(
                fee_quoter_setup::get_dest_chain_selector(),
                token_addr,
                fee_token_amount,
                extra_args,
                vector[token_addr], // local_token_addresses,
                vector[dest_token_address], //dest_token_addresses,
                vector[dest_pool_data] // dest_pool_datas
            );

        assert!(
            msg_fee_juels
                == (fee_token_amount as u256) * LOCAL_8_TO_18_DECIMALS_LINK_MULTIPLIER
        ); // Same token, so amount stays the same
        assert!(is_out_of_order_execution == true); // We set OOO to true in extra args
        assert!(converted_extra_args.length() > 0); // Should have non-empty converted args
        assert!(dest_exec_data_per_token.length() == 1); // Should have one entry for our token
    }
}
