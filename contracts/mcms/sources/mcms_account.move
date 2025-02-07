module mcms::mcms_account {
    use std::account::{Self, SignerCapability};
    use std::resource_account;

    friend mcms::mcms;
    friend mcms::mcms_registry;

    struct MCMSAccountState has key, store {
        signer_cap: SignerCapability
    }

    fun init_module(publisher: &signer) {
        let signer_cap =
            resource_account::retrieve_resource_account_cap(publisher, @mcms_deployer);
        move_to(publisher, MCMSAccountState { signer_cap });
    }

    public(friend) fun get_signer(): signer acquires MCMSAccountState {
        let state = borrow_global<MCMSAccountState>(@mcms);
        account::create_signer_with_capability(&state.signer_cap)
    }
}
