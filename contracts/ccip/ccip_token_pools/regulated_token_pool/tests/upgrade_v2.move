#[test_only]
module regulated_token_pool::upgrade_v2 {
    use std::account::{Self};

    use regulated_token::regulated_token::{Self};
    use regulated_token_pool::regulated_token_pool;

    use ccip::token_admin_registry::{Self};

    fun init_module(publisher: &signer) {
        // register the pool on deployment, because in the case of object code deployment,
        // this is the only time we have a signer ref to @regulated_token_pool.

        // create an Account on the object for event handles.
        account::create_account_if_does_not_exist(@regulated_token_pool);

        // the name of this module. if incorrect, callbacks will fail to be registered and
        // register_pool will revert.
        let token_pool_module_name = b"regulated_token_pool";

        let regulated_token_address = regulated_token::token_address();

        let lock_or_burn_closure =
            |fa, input| regulated_token_pool::lock_or_burn_v2(fa, input);
        let release_or_mint_closure =
            |input| regulated_token_pool::release_or_mint_v2(input);

        // If the contract has already been deployed with V1 and needs to be upgraded to V2,
        // create a new module and pass in `publisher` from `fun init_module(publisher: &signer)`
        token_admin_registry::register_pool_v2(
            publisher,
            token_pool_module_name,
            regulated_token_address,
            lock_or_burn_closure,
            release_or_mint_closure,
            regulated_token_pool::create_callback_proof()
        );
    }

    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }
}
