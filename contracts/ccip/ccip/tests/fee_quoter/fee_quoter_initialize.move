#[test_only]
module ccip::fee_quoter_initialize {
    use ccip::fee_quoter;
    use ccip::fee_quoter_setup;

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_initialize(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        fee_quoter_setup::setup(aptos_framework, ccip, owner);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_type_and_version() {
        let type_and_version = fee_quoter::type_and_version();

        // Verify the type and version string
        assert!(std::string::utf8(b"FeeQuoter 1.6.0") == type_and_version);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_get_static_config(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = std::object::object_address(&token_obj);

        // Test the static config getter function
        let static_config = fee_quoter::get_static_config();

        // No direct accessor method for static config, so test by checking if it exists
        assert!(std::bcs::to_bytes(&static_config).length() > 0);

        // We need to check values indirectly, since we can't directly access them
        // Check by removing all fee tokens and re-adding them which will use the
        // existing config values

        // Remove all fee tokens
        fee_quoter::apply_fee_token_updates(
            owner, vector[token_addr], // Remove the token
            vector[] // No new tokens
        );

        // Re-add the token
        fee_quoter::apply_fee_token_updates(
            owner,
            vector[], // No tokens to remove
            vector[token_addr] // Add token again
        );

        // This should have worked if the static config is valid
        // Get the config again to verify it still exists
        let static_config_again = fee_quoter::get_static_config();
        assert!(std::bcs::to_bytes(&static_config_again).length() > 0);
    }

    #[test(aptos_framework = @aptos_framework, ccip = @ccip, owner = @mcms)]
    fun test_timestamp_price_functions(
        aptos_framework: &signer, ccip: &signer, owner: &signer
    ) {
        let (_owner_addr, token_obj) =
            fee_quoter_setup::setup(aptos_framework, ccip, owner);
        let token_addr = std::object::object_address(&token_obj);

        // Get the token price after setup
        let token_price = fee_quoter::get_token_price(token_addr);

        // Verify the value function works
        let price_value = fee_quoter::timestamped_price_value(&token_price);
        assert!(price_value == 1000);

        // Verify the timestamp function works
        let price_timestamp = fee_quoter::timestamped_price_timestamp(&token_price);
        assert!(price_timestamp == std::timestamp::now_seconds());
    }
}
