/// This module manages the ownership of the MCMS package.
module mcms::mcms_account {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::event;
    use std::resource_account;
    use std::signer;

    friend mcms::mcms;
    friend mcms::mcms_deployer;
    friend mcms::mcms_registry;

    struct AccountState has key, store {
        signer_cap: SignerCapability,
        owner: address,
        pending_owner: address
    }

    #[event]
    struct OwnershipTransferRequested has store, drop {
        from: address,
        to: address
    }

    #[event]
    struct OwnershipTransferred has store, drop {
        from: address,
        to: address
    }

    const E_CANNOT_TRANSFER_TO_SELF: u64 = 1;
    const E_MUST_BE_PROPOSED_OWNER: u64 = 2;
    const E_UNAUTHORIZED: u64 = 3;

    fun init_module(publisher: &signer) {
        let signer_cap =
            resource_account::retrieve_resource_account_cap(publisher, @mcms_owner);
        init_module_internal(publisher, signer_cap);
    }

    inline fun init_module_internal(
        publisher: &signer, signer_cap: SignerCapability
    ) {
        move_to(
            publisher,
            AccountState {
                signer_cap,
                owner: @mcms_owner,
                pending_owner: @0x0
            }
        );
    }

    /// Transfers ownership to the specified address.
    public entry fun transfer_ownership(caller: &signer, to: address) acquires AccountState {
        let state = borrow_state_mut();

        assert_is_owner_internal(state, caller);

        assert!(
            signer::address_of(caller) != to,
            error::invalid_argument(E_CANNOT_TRANSFER_TO_SELF)
        );

        state.pending_owner = to;

        event::emit(OwnershipTransferRequested { from: state.owner, to });
    }

    /// Transfers ownership back to the `@mcms` address.
    public entry fun transfer_ownership_to_self(caller: &signer) acquires AccountState {
        transfer_ownership(caller, @mcms);
    }

    /// Accepts ownership transfer. Can only be called by the pending owner.
    public entry fun accept_ownership(caller: &signer) acquires AccountState {
        let state = borrow_state_mut();

        let caller_address = signer::address_of(caller);
        assert!(
            caller_address == state.pending_owner,
            error::permission_denied(E_MUST_BE_PROPOSED_OWNER)
        );

        let previous_owner = state.owner;
        state.owner = caller_address;
        state.pending_owner = @0x0;

        event::emit(OwnershipTransferred { from: previous_owner, to: state.owner });
    }

    #[view]
    /// Returns the current owner.
    public fun owner(): address acquires AccountState {
        borrow_state().owner
    }

    #[view]
    /// Returns `true` if the module is self-owned (owned by `@mcms`).
    public fun is_self_owned(): bool acquires AccountState {
        owner() == @mcms
    }

    public(friend) fun get_signer(): signer acquires AccountState {
        account::create_signer_with_capability(&borrow_state().signer_cap)
    }

    public(friend) fun assert_is_owner(caller: &signer) acquires AccountState {
        assert_is_owner_internal(borrow_state(), caller);
    }

    inline fun assert_is_owner_internal(
        state: &AccountState, caller: &signer
    ) {
        assert!(
            state.owner == signer::address_of(caller),
            error::permission_denied(E_UNAUTHORIZED)
        );
    }

    inline fun borrow_state(): &AccountState {
        borrow_global<AccountState>(@mcms)
    }

    inline fun borrow_state_mut(): &mut AccountState {
        borrow_global_mut<AccountState>(@mcms)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        let test_signer_cap = account::create_test_signer_cap(@mcms);
        init_module_internal(publisher, test_signer_cap);
    }
}
