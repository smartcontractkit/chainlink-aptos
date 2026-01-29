#[test_only]
module usdc_token_pool::upgrade_v2 {
    use std::account::{Self};
    use std::error;
    use std::fungible_asset::{Metadata};
    use std::object::{Self};

    use usdc_token_pool::usdc_token_pool;

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

        // If the contract has already been deployed with V1 and needs to be upgraded to V2,
        // create a new module and pass in `publisher` from `fun init_module(publisher: &signer)`
        usdc_token_pool::register_v2_callbacks(publisher);
    }

    #[test_only]
    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }
}
