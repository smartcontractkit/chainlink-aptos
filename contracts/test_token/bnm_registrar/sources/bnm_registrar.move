module test_token::bnm_registrar {
    use test_token::test_token;
    use burn_mint_token_pool::burn_mint_token_pool;


    public entry fun initialize(signer: &signer) {
        let burn_ref = test_token::get_additional_burn_ref(signer);
        let mint_ref = test_token::get_additional_mint_ref(signer);
        
        burn_mint_token_pool::initialize(signer, burn_ref, mint_ref);
    }
}
