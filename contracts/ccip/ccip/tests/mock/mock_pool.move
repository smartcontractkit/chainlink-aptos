#[test_only]
module 0x662d86e29929eb0637ba20d8926e91ffc74f59580cf18874b366b3150300561f::mock_pool {
    use std::fungible_asset::{Self, FungibleAsset, TransferRef};
    use std::object::{Object};
    use ccip::token_admin_registry;
    use std::signer;

    const MOCK_POOL_MODULE_NAME: vector<u8> = b"mock_pool";

    struct TestProof has drop {}

    public fun register_and_set_pool(
        owner: &signer, mock_obj_signer: &signer, local_token: address
    ) {
        register_pool(mock_obj_signer, local_token);
        set_admin(owner, local_token);
        token_admin_registry::set_pool(
            owner, local_token, signer::address_of(mock_obj_signer)
        );
    }

    public fun register_pool(
        mock_obj_signer: &signer, local_token: address
    ) {
        token_admin_registry::register_pool<TestProof>(
            mock_obj_signer,
            MOCK_POOL_MODULE_NAME,
            local_token,
            TestProof {}
        );
    }

    inline fun set_admin(owner: &signer, local_token: address) {
        token_admin_registry::propose_administrator(
            owner, local_token, signer::address_of(owner)
        );
        token_admin_registry::accept_admin_role(owner, local_token);
    }

    public fun lock_or_burn<T: key>(
        store: Object<T>, fa: FungibleAsset, _transfer_ref: &TransferRef
    ) {
        fungible_asset::deposit(store, fa);
    }

    public fun release_or_mint<T: key>(
        _store: Object<T>, _amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset {
        let metadata = fungible_asset::transfer_ref_metadata(transfer_ref);
        fungible_asset::zero(metadata)
    }
}
