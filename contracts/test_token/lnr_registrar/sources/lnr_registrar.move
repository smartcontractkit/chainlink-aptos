module test_token::lnr_registrar {
    use std::option;
    use std::signer;
    use test_token::test_token;
    use lock_release_token_pool::lock_release_token_pool;

    public entry fun initialize(caller: &signer) {
        let transfer_ref = test_token::get_additional_transfer_ref(caller);

        lock_release_token_pool::initialize(
            caller, option::some(transfer_ref), signer::address_of(caller)
        );
    }

    public entry fun initialize_without_transfer_ref(caller: &signer) {
        lock_release_token_pool::initialize(
            caller, option::none(), signer::address_of(caller)
        )
    }
}
