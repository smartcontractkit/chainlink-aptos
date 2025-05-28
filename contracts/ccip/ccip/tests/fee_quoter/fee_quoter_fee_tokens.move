#[test_only]
module ccip::fee_quoter_fee_tokens {
    use std::object;
    use std::vector;
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_apply_fee_token_updates(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Create a second token to add/remove
        let (_second_token_obj, second_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"second_token");

        // Initial state should have our first token
        let fee_tokens = fee_quoter::get_fee_tokens();
        assert!(fee_tokens.length() == 1);
        assert!(fee_tokens[0] == token_addr);

        // Add the second token
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[], // fee_tokens_to_remove
            vector[second_token_addr] // fee_tokens_to_add
        );

        // Verify both tokens are present
        fee_tokens = fee_quoter::get_fee_tokens();
        assert!(fee_tokens.length() == 2);
        assert!(vector::contains(&fee_tokens, &second_token_addr));

        // Now remove the first token
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[token_addr], // fee_tokens_to_remove
            vector[] // fee_tokens_to_add
        );

        // Verify only second token remains
        fee_tokens = fee_quoter::get_fee_tokens();
        assert!(fee_tokens.length() == 1);
        assert!(fee_tokens[0] == second_token_addr);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_apply_premium_multiplier_wei_per_eth_updates(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = object::object_address(&token_obj);

        // Initial premium multiplier is 1 from setup
        let initial_multiplier =
            fee_quoter::get_premium_multiplier_wei_per_eth(token_addr);
        assert!(initial_multiplier == 1);

        // Update premium multiplier
        let new_multiplier = 2000000000000000000; // 2e18, or 200%
        fee_quoter::apply_premium_multiplier_wei_per_eth_updates(
            owner,
            vector[token_addr], // tokens
            vector[new_multiplier] // premium_multiplier_wei_per_eth
        );

        // Verify updated premium multiplier
        let updated_multiplier =
            fee_quoter::get_premium_multiplier_wei_per_eth(token_addr);
        assert!(updated_multiplier == new_multiplier);
    }

    #[
        test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms),
        expected_failure(abort_code = 65545, location = ccip::fee_quoter) // E_FEE_TOKEN_NOT_SUPPORTED
    ]
    fun test_unsupported_fee_token_reverts(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let _token_addr = object::object_address(&token_obj);

        // Create a token that's not in the fee token list
        let (_unsupported_token_obj, unsupported_token_addr) =
            fee_quoter_setup::create_test_token(owner, b"unsupported_token");

        // Create EVM-compatible receiver address
        let receiver = fee_quoter_setup::create_evm_receiver_address();

        // Create extra args with gas limit
        let extra_args = fee_quoter_setup::create_extra_args(500000, true);

        // Try to use an unsupported token as fee token
        fee_quoter::get_validated_fee(
            fee_quoter_setup::get_dest_chain_selector(),
            receiver,
            b"test data",
            vector[], // token addresses
            vector[], // token amounts
            vector[], // token store addresses
            unsupported_token_addr, // Unsupported fee token
            @0x0, // fee token store
            extra_args // extra args
        );
    }
}
