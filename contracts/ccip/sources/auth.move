/// The auth module provides authentication and authorization functionality for CCIP.
module chainlink_ccip::auth {
    use std::string::{Self, String};
    use std::vector;
    
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use sui::dynamic_field as df;
    
    use chainlink_ccip::allowlist::{Self, AllowlistState};
    use chainlink_ccip::ownable::{Self, OwnableState};
    use chainlink_ccip::state_object::{Self, StateObject, StateObjectCap};
    
    use chainlink_mcms::bcs_stream;
    use chainlink_mcms::params;
    
    // Error codes
    const E_UNKNOWN_FUNCTION: u64 = 1;
    const E_NOT_ALLOWED_ONRAMP: u64 = 2;
    const E_NOT_ALLOWED_OFFRAMP: u64 = 3;
    const E_NOT_OWNER_OR_CCIP: u64 = 4;
    
    // Field keys for dynamic fields
    struct OnrampsKey has copy, drop, store {}
    struct OfframpsKey has copy, drop, store {}
    struct OwnableKey has copy, drop, store {}
    
    struct AdminCap has key, store {
        id: UID
    }
    
    // One-time initialization function
    fun init(ctx: &mut TxContext) {
        // Create admin capability
        let admin_cap = AdminCap {
            id: object::new(ctx)
        };
        
        // Create the allowed onramps allowlist
        let allowed_onramps = allowlist::new_with_name(
            vector[], string::utf8(b"onramps")
        );
        allowlist::set_allowlist_enabled(&mut allowed_onramps, true);
        
        // Create the allowed offramps allowlist
        let allowed_offramps = allowlist::new_with_name(
            vector[], string::utf8(b"offramps")
        );
        allowlist::set_allowlist_enabled(&mut allowed_offramps, true);
        
        // Get the state object
        let state_object = state_object::init_for_testing(ctx);
        
        // Add dynamic fields to the state object
        df::add(&mut state_object.id, OnrampsKey {}, allowed_onramps);
        df::add(&mut state_object.id, OfframpsKey {}, allowed_offramps);
        df::add(
            &mut state_object.id, 
            OwnableKey {}, 
            ownable::new(tx_context::sender(ctx))
        );
        
        // Transfer the admin capability to the sender
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }
    
    // View functions
    public fun get_allowed_onramps(state_obj: &StateObject): vector<address> {
        let allowed_onramps = df::borrow<OnrampsKey, AllowlistState>(
            &state_obj.id, OnrampsKey {}
        );
        allowlist::get_allowlist(allowed_onramps)
    }
    
    public fun get_allowed_offramps(state_obj: &StateObject): vector<address> {
        let allowed_offramps = df::borrow<OfframpsKey, AllowlistState>(
            &state_obj.id, OfframpsKey {}
        );
        allowlist::get_allowlist(allowed_offramps)
    }
    
    public fun is_onramp_allowed(state_obj: &StateObject, onramp_address: address): bool {
        let allowed_onramps = df::borrow<OnrampsKey, AllowlistState>(
            &state_obj.id, OnrampsKey {}
        );
        allowlist::is_allowed(allowed_onramps, onramp_address)
    }
    
    public fun is_offramp_allowed(state_obj: &StateObject, offramp_address: address): bool {
        let allowed_offramps = df::borrow<OfframpsKey, AllowlistState>(
            &state_obj.id, OfframpsKey {}
        );
        allowlist::is_allowed(allowed_offramps, offramp_address)
    }
    
    // Entry functions
    public entry fun apply_allowed_onramp_updates(
        _: &AdminCap,
        state_obj: &mut StateObject,
        onramps_to_remove: vector<address>,
        onramps_to_add: vector<address>,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let ownable_state = df::borrow<OwnableKey, OwnableState>(
            &state_obj.id, OwnableKey {}
        );
        
        assert_is_owner_or_ccip(caller, ownable_state);
        
        let allowed_onramps = df::borrow_mut<OnrampsKey, AllowlistState>(
            &mut state_obj.id, OnrampsKey {}
        );
        
        allowlist::apply_allowlist_updates(
            allowed_onramps,
            onramps_to_remove,
            onramps_to_add
        );
    }
    
    public entry fun apply_allowed_offramp_updates(
        _: &AdminCap,
        state_obj: &mut StateObject,
        offramps_to_remove: vector<address>,
        offramps_to_add: vector<address>,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let ownable_state = df::borrow<OwnableKey, OwnableState>(
            &state_obj.id, OwnableKey {}
        );
        
        assert_is_owner_or_ccip(caller, ownable_state);
        
        let allowed_offramps = df::borrow_mut<OfframpsKey, AllowlistState>(
            &mut state_obj.id, OfframpsKey {}
        );
        
        allowlist::apply_allowlist_updates(
            allowed_offramps,
            offramps_to_remove,
            offramps_to_add
        );
    }
    
    // Helper functions
    fun assert_is_owner_or_ccip(
        caller: address, ownable_state: &OwnableState
    ) {
        assert!(
            caller == @chainlink_ccip || caller == ownable::owner(ownable_state),
            E_NOT_OWNER_OR_CCIP
        );
    }
    
    public fun assert_is_allowed_onramp(state_obj: &StateObject, caller: address) {
        let allowed_onramps = df::borrow<OnrampsKey, AllowlistState>(
            &state_obj.id, OnrampsKey {}
        );
        assert!(
            allowlist::is_allowed(allowed_onramps, caller),
            E_NOT_ALLOWED_ONRAMP
        );
    }
    
    public fun assert_is_allowed_offramp(state_obj: &StateObject, caller: address) {
        let allowed_offramps = df::borrow<OfframpsKey, AllowlistState>(
            &state_obj.id, OfframpsKey {}
        );
        assert!(
            allowlist::is_allowed(allowed_offramps, caller),
            E_NOT_ALLOWED_OFFRAMP
        );
    }
    
    // Ownership functions
    public fun owner(state_obj: &StateObject): address {
        let ownable_state = df::borrow<OwnableKey, OwnableState>(
            &state_obj.id, OwnableKey {}
        );
        ownable::owner(ownable_state)
    }
    
    public fun assert_only_owner(state_obj: &StateObject, caller: address) {
        let ownable_state = df::borrow<OwnableKey, OwnableState>(
            &state_obj.id, OwnableKey {}
        );
        ownable::assert_only_owner(caller, ownable_state);
    }
    
    public entry fun transfer_ownership(
        _: &AdminCap,
        state_obj: &mut StateObject,
        to: address,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let ownable_state = df::borrow_mut<OwnableKey, OwnableState>(
            &mut state_obj.id, OwnableKey {}
        );
        
        ownable::transfer_ownership(caller, ownable_state, to);
    }
    
    public entry fun accept_ownership(
        state_obj: &mut StateObject,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let ownable_state = df::borrow_mut<OwnableKey, OwnableState>(
            &mut state_obj.id, OwnableKey {}
        );
        
        ownable::accept_ownership(caller, ownable_state);
    }
    
    public entry fun execute_ownership_transfer(
        _: &AdminCap,
        state_obj: &mut StateObject,
        to: address,
        ctx: &mut TxContext
    ) {
        let ownable_state = df::borrow_mut<OwnableKey, OwnableState>(
            &mut state_obj.id, OwnableKey {}
        );
        
        ownable::execute_ownership_transfer(ctx, ownable_state, to);
    }
    
    // MCMS integration would be implemented differently in Sui
    // This is a placeholder for the MCMS entrypoint functionality
    struct McmsCallback has drop {}
}
