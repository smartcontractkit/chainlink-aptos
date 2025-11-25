#[test_only]
module usdc_token_pool::upgrade_v2 {
    use std::account::{Self};
    use std::error;
    use std::fungible_asset::{Metadata};
    use std::object::{Self};

    use usdc_token_pool::usdc_token_pool;

    use ccip::token_admin_registry::{Self};

    const E_INVALID_FUNGIBLE_ASSET: u64 = 1;

    fun init_module(publisher: &signer) {
        // register the pool on deployment, because in the case of object code deployment,
        // this is the only time we have a signer ref to @usdc_token_pool.
        assert!(
            object::object_exists<Metadata>(@local_token),
            error::invalid_argument(E_INVALID_FUNGIBLE_ASSET)
        );

        // create an Account on the object for event handles.
        account::create_account_if_does_not_exist(@usdc_token_pool);

        // the name of this module. if incorrect, callbacks will fail to be registered and
        // register_pool will revert.
        let token_pool_module_name = b"usdc_token_pool";

        let lock_or_burn_closure = |fa, input| usdc_token_pool::lock_or_burn_v2(
            fa, input
        );
        let release_or_mint_closure = |input| usdc_token_pool::release_or_mint_v2(input);

        // If the contract has already been deployed with V1 and needs to be upgraded to V2,
        // create a new module
        token_admin_registry::register_pool_v2(
            publisher,
            token_pool_module_name,
            @local_token,
            lock_or_burn_closure,
            release_or_mint_closure,
            usdc_token_pool::create_callback_proof()
        );
    }

    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }
}
