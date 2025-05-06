/// The ownable module provides functionality for managing ownership of objects.
module chainlink_ccip::ownable {
    use std::string::{Self, String};
    
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    
    // Error codes
    const E_NOT_OWNER: u64 = 1;
    const E_NOT_PENDING_OWNER: u64 = 2;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 3;
    
    struct OwnableState has store {
        owner: address,
        pending_owner: address
    }
    
    // Events
    struct OwnershipTransferRequested has copy, drop {
        from: address,
        to: address
    }
    
    struct OwnershipTransferred has copy, drop {
        from: address,
        to: address
    }
    
    public fun new(owner: address): OwnableState {
        OwnableState {
            owner,
            pending_owner: @0x0
        }
    }
    
    public fun owner(state: &OwnableState): address {
        state.owner
    }
    
    public fun pending_owner(state: &OwnableState): address {
        state.pending_owner
    }
    
    public fun assert_only_owner(caller: address, state: &OwnableState) {
        assert!(caller == state.owner, E_NOT_OWNER);
    }
    
    public fun transfer_ownership(
        caller: address, state: &mut OwnableState, to: address
    ) {
        assert_only_owner(caller, state);
        assert!(state.owner != to, E_CANNOT_TRANSFER_TO_SELF);
        
        state.pending_owner = to;
        
        event::emit(OwnershipTransferRequested { from: state.owner, to });
    }
    
    public fun accept_ownership(caller: address, state: &mut OwnableState) {
        assert!(caller == state.pending_owner, E_NOT_PENDING_OWNER);
        
        let old_owner = state.owner;
        state.owner = state.pending_owner;
        state.pending_owner = @0x0;
        
        event::emit(OwnershipTransferred { from: old_owner, to: state.owner });
    }
    
    public fun execute_ownership_transfer(
        caller: &TxContext, state: &mut OwnableState, to: address
    ) {
        let caller_address = tx_context::sender(caller);
        assert_only_owner(caller_address, state);
        
        let old_owner = state.owner;
        state.owner = to;
        state.pending_owner = @0x0;
        
        event::emit(OwnershipTransferred { from: old_owner, to });
    }
}
