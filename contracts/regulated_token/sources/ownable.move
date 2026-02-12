/// This module implements an Ownable component similar to Ownable2Step.sol for managing
/// object ownership.
///
/// Due to Aptos's security model requiring the original owner's signer for 0x1::object::transfer,
/// this implementation uses a 3-step ownership transfer flow:
///
/// 1. Initial owner calls transfer_ownership with the new owner's address
/// 2. Pending owner calls accept_ownership to confirm the transfer
/// 3. Initial owner calls execute_ownership_transfer to complete the transfer
///
/// The execute_ownership_transfer function requires a signer in order to perform the
/// object transfer, while other operations only require the caller address to maintain the
/// principle of least privilege.
///
/// Note that direct ownership transfers via 0x1::object::transfer are still possible.
/// This module handles such cases gracefully by reading the current owner directly
/// from the object.
module regulated_token::ownable {
    use std::account;
    use std::error;
    use std::event::{Self, EventHandle};
    use std::object::{Self, Object, ObjectCore};
    use std::option::{Self, Option};
    use std::signer;

    struct OwnableState has store {
        target_object: Object<ObjectCore>,
        pending_transfer: Option<PendingTransfer>,
        ownership_transfer_requested_events: EventHandle<OwnershipTransferRequested>,
        ownership_transfer_accepted_events: EventHandle<OwnershipTransferAccepted>,
        ownership_transferred_events: EventHandle<OwnershipTransferred>
    }

    struct PendingTransfer has store, drop {
        from: address,
        to: address,
        accepted: bool
    }

    const E_MUST_BE_PROPOSED_OWNER: u64 = 1;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 2;
    const E_ONLY_CALLABLE_BY_OWNER: u64 = 3;
    const E_PROPOSED_OWNER_MISMATCH: u64 = 4;
    const E_OWNER_CHANGED: u64 = 5;
    const E_NO_PENDING_TRANSFER: u64 = 6;
    const E_TRANSFER_NOT_ACCEPTED: u64 = 7;
    const E_TRANSFER_ALREADY_ACCEPTED: u64 = 8;

    #[event]
    struct OwnershipTransferRequested has store, drop {
        from: address,
        to: address
    }

    #[event]
    struct OwnershipTransferAccepted has store, drop {
        from: address,
        to: address
    }

    #[event]
    struct OwnershipTransferred has store, drop {
        from: address,
        to: address
    }

    public fun new(event_account: &signer, object_address: address): OwnableState {
        let new_state = OwnableState {
            target_object: object::address_to_object<ObjectCore>(object_address),
            pending_transfer: option::none(),
            ownership_transfer_requested_events: account::new_event_handle(event_account),
            ownership_transfer_accepted_events: account::new_event_handle(event_account),
            ownership_transferred_events: account::new_event_handle(event_account)
        };

        new_state
    }

    public fun owner(state: &OwnableState): address {
        owner_internal(state)
    }

    public fun has_pending_transfer(state: &OwnableState): bool {
        state.pending_transfer.is_some()
    }

    public fun pending_transfer_from(state: &OwnableState): Option<address> {
        state.pending_transfer.map_ref(|pending_transfer| pending_transfer.from)
    }

    public fun pending_transfer_to(state: &OwnableState): Option<address> {
        state.pending_transfer.map_ref(|pending_transfer| pending_transfer.to)
    }

    public fun pending_transfer_accepted(state: &OwnableState): Option<bool> {
        state.pending_transfer.map_ref(|pending_transfer| pending_transfer.accepted)
    }

    inline fun owner_internal(state: &OwnableState): address {
        object::owner(state.target_object)
    }

    public fun transfer_ownership(
        caller: &signer, state: &mut OwnableState, to: address
    ) {
        let caller_address = signer::address_of(caller);
        assert_only_owner_internal(caller_address, state);
        assert!(caller_address != to, error::invalid_argument(E_CANNOT_TRANSFER_TO_SELF));

        state.pending_transfer = option::some(
            PendingTransfer { from: caller_address, to, accepted: false }
        );

        event::emit_event(
            &mut state.ownership_transfer_requested_events,
            OwnershipTransferRequested { from: caller_address, to }
        );
    }

    public fun accept_ownership(caller: &signer, state: &mut OwnableState) {
        let caller_address = signer::address_of(caller);
        assert!(
            state.pending_transfer.is_some(),
            error::permission_denied(E_NO_PENDING_TRANSFER)
        );

        let current_owner = owner_internal(state);
        let pending_transfer = state.pending_transfer.borrow_mut();

        // check that the owner has not changed from a direct call to 0x1::object::transfer,
        // in which case the transfer flow should be restarted.
        assert!(
            pending_transfer.from == current_owner,
            error::permission_denied(E_OWNER_CHANGED)
        );
        assert!(
            pending_transfer.to == caller_address,
            error::permission_denied(E_MUST_BE_PROPOSED_OWNER)
        );
        assert!(
            !pending_transfer.accepted,
            error::invalid_state(E_TRANSFER_ALREADY_ACCEPTED)
        );

        pending_transfer.accepted = true;

        event::emit_event(
            &mut state.ownership_transfer_accepted_events,
            OwnershipTransferAccepted { from: pending_transfer.from, to: caller_address }
        );
    }

    public fun execute_ownership_transfer(
        caller: &signer, state: &mut OwnableState, to: address
    ) {
        let caller_address = signer::address_of(caller);
        assert_only_owner_internal(caller_address, state);

        let current_owner = owner_internal(state);
        let pending_transfer = state.pending_transfer.extract();

        // check that the owner has not changed from a direct call to 0x1::object::transfer,
        // in which case the transfer flow should be restarted.
        assert!(
            pending_transfer.from == current_owner,
            error::permission_denied(E_OWNER_CHANGED)
        );
        assert!(
            pending_transfer.to == to,
            error::permission_denied(E_PROPOSED_OWNER_MISMATCH)
        );
        assert!(
            pending_transfer.accepted,
            error::invalid_state(E_TRANSFER_NOT_ACCEPTED)
        );

        object::transfer(caller, state.target_object, pending_transfer.to);
        state.pending_transfer = option::none();

        event::emit_event(
            &mut state.ownership_transferred_events,
            OwnershipTransferred { from: caller_address, to }
        );
    }

    public fun assert_only_owner(caller: address, state: &OwnableState) {
        assert_only_owner_internal(caller, state)
    }

    inline fun assert_only_owner_internal(
        caller: address, state: &OwnableState
    ) {
        assert!(
            caller == owner_internal(state),
            error::permission_denied(E_ONLY_CALLABLE_BY_OWNER)
        );
    }

    public fun destroy(state: OwnableState) {
        let OwnableState {
            target_object: _,
            pending_transfer: _,
            ownership_transfer_requested_events,
            ownership_transfer_accepted_events,
            ownership_transferred_events
        } = state;

        event::destroy_handle(ownership_transfer_requested_events);
        event::destroy_handle(ownership_transfer_accepted_events);
        event::destroy_handle(ownership_transferred_events);
    }

    #[test_only]
    public fun get_ownership_transfer_requested_events(
        state: &OwnableState
    ): &EventHandle<OwnershipTransferRequested> {
        &state.ownership_transfer_requested_events
    }

    #[test_only]
    public fun get_ownership_transfer_accepted_events(
        state: &OwnableState
    ): &EventHandle<OwnershipTransferAccepted> {
        &state.ownership_transfer_accepted_events
    }

    #[test_only]
    public fun get_ownership_transferred_events(
        state: &OwnableState
    ): &EventHandle<OwnershipTransferred> {
        &state.ownership_transferred_events
    }
}
