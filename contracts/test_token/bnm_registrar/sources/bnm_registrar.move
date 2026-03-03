module test_token::bnm_registrar {
    use test_token::test_token;
    use burn_mint_token_pool::burn_mint_token_pool;

    public entry fun initialize(caller: &signer) {
        let burn_ref = test_token::get_additional_burn_ref(caller);
        let mint_ref = test_token::get_additional_mint_ref(caller);

        burn_mint_token_pool::initialize(caller, burn_ref, mint_ref);
    }
}
