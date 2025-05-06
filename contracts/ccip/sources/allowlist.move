/// The allowlist module provides functionality for managing a list of allowed addresses.
module chainlink_ccip::allowlist {
    use std::string::{Self, String};
    use std::vector;
    
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    use sui::table::{Self, Table};
    
    // Error codes
    const E_ALLOWLIST_NOT_ENABLED: u64 = 1;
    
    public struct AllowlistState has store {
        allowlist_name: String,
        allowlist_enabled: bool,
        allowlist: vector<address>
    }
    
    // Events
    public struct AllowlistRemove has copy, drop {
        allowlist_name: String,
        removed_address: address
    }
    
    public struct AllowlistAdd has copy, drop {
        allowlist_name: String,
        added_address: address
    }
    
    public fun new(allowlist: vector<address>): AllowlistState {
        new_with_name(allowlist, string::utf8(b"default"))
    }
    
    public fun new_with_name(
        allowlist: vector<address>, allowlist_name: String
    ): AllowlistState {
        AllowlistState {
            allowlist_name,
            allowlist_enabled: !vector::is_empty(&allowlist),
            allowlist
        }
    }
    
    public fun get_allowlist_enabled(state: &AllowlistState): bool {
        state.allowlist_enabled
    }
    
    public fun set_allowlist_enabled(
        state: &mut AllowlistState, enabled: bool
    ) {
        state.allowlist_enabled = enabled;
    }
    
    public fun get_allowlist(state: &AllowlistState): vector<address> {
        state.allowlist
    }
    
    public fun is_allowed(state: &AllowlistState, sender: address): bool {
        if (!state.allowlist_enabled) {
            return true
        };
        
        vector::contains(&state.allowlist, &sender)
    }
    
    public fun apply_allowlist_updates(
        state: &mut AllowlistState, removes: vector<address>, adds: vector<address>
    ) {
        let mut i = 0;
        let mut len = vector::length(&removes);
        
        while (i < len) {
            let removed_address = *vector::borrow(&removes, i);
            let (found, idx) = vector::index_of(&state.allowlist, &removed_address);
            if (found) {
                vector::swap_remove(&mut state.allowlist, idx);
                event::emit(
                    AllowlistRemove {
                        allowlist_name: state.allowlist_name,
                        removed_address
                    }
                );
            };
            i = i + 1;
        };
        
        if (!vector::is_empty(&adds)) {
            assert!(
                state.allowlist_enabled,
                E_ALLOWLIST_NOT_ENABLED
            );
            
            i = 0;
            len = vector::length(&adds);
            
            while (i < len) {
                let added_address = *vector::borrow(&adds, i);
                if (added_address != @0x0
                    && !vector::contains(&state.allowlist, &added_address)) {
                    vector::push_back(&mut state.allowlist, added_address);
                    event::emit(
                        AllowlistAdd {
                            allowlist_name: state.allowlist_name,
                            added_address
                        }
                    );
                };
                i = i + 1;
            };
        }
    }
    
    public fun destroy_allowlist(state: AllowlistState) {
        let AllowlistState {
            allowlist_name: _,
            allowlist_enabled: _,
            allowlist: _
        } = state;
    }
    
    #[test_only]
    public fun new_add_event(add: address): AllowlistAdd {
        AllowlistAdd { added_address: add, allowlist_name: string::utf8(b"default") }
    }
    
    #[test_only]
    public fun new_remove_event(remove: address): AllowlistRemove {
        AllowlistRemove {
            removed_address: remove,
            allowlist_name: string::utf8(b"default")
        }
    }
}

#[test_only]
module chainlink_ccip::allowlist_test {
    use std::vector;
    use sui::test_scenario::{Self as ts, Scenario};
    
    use chainlink_ccip::allowlist;
    
    #[test]
    fun init_empty_is_empty_and_disabled() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            let mut state = allowlist::new(vector::empty());
            
            assert!(!allowlist::get_allowlist_enabled(&state));
            assert!(vector::is_empty(&allowlist::get_allowlist(&state)));
            
            // Any address is allowed when the allowlist is disabled
            assert!(allowlist::is_allowed(&state, @0x1111111111111));
            
            allowlist::destroy_allowlist(state);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    fun init_non_empty_is_non_empty_and_enabled() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            let init_allowlist = vector[@0x1, @0x2];
            
            let mut state = allowlist::new(init_allowlist);
            
            assert!(allowlist::get_allowlist_enabled(&state));
            assert!(vector::length(&allowlist::get_allowlist(&state)) == 2);
            
            // The given addresses are allowed
            assert!(allowlist::is_allowed(&state, @0x1));
            assert!(allowlist::is_allowed(&state, @0x2));
            
            // Other addresses are not allowed
            assert!(!allowlist::is_allowed(&state, @0x3));
            
            allowlist::destroy_allowlist(state);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    #[expected_failure(abort_code = 0x1, location = chainlink_ccip::allowlist)]
    fun cannot_add_to_disabled_allowlist() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            let mut state = allowlist::new(vector::empty());
            
            let adds = vector[@0x1];
            
            allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds);
            
            allowlist::destroy_allowlist(state);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    fun apply_allowlist_updates_mutates_state() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            let mut state = allowlist::new(vector::empty());
            allowlist::set_allowlist_enabled(&mut state, true);
            
            assert!(vector::is_empty(&allowlist::get_allowlist(&state)));
            
            allowlist::apply_allowlist_updates(&mut state, vector::empty(), vector::empty());
            
            assert!(vector::is_empty(&allowlist::get_allowlist(&state)));
            
            let adds = vector[@0x1, @0x2];
            
            allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds);
            
            let removes = vector[@0x1];
            
            allowlist::apply_allowlist_updates(&mut state, removes, vector::empty());
            
            assert!(vector::length(&allowlist::get_allowlist(&state)) == 1);
            assert!(allowlist::is_allowed(&state, @0x2));
            assert!(!allowlist::is_allowed(&state, @0x1));
            
            allowlist::destroy_allowlist(state);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    fun apply_allowlist_updates_removes_before_adds() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            let account_to_allow = @0x1;
            let mut state = allowlist::new(vector::empty());
            allowlist::set_allowlist_enabled(&mut state, true);
            
            let adds_and_removes = vector[account_to_allow];
            
            allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds_and_removes);
            
            assert!(vector::length(&allowlist::get_allowlist(&state)) == 1);
            assert!(allowlist::is_allowed(&state, account_to_allow));
            
            allowlist::apply_allowlist_updates(&mut state, adds_and_removes, adds_and_removes);
            
            // Since removes happen before adds, the account should still be allowed
            assert!(allowlist::is_allowed(&state, account_to_allow));
            
            allowlist::destroy_allowlist(state);
        };
        
        ts::end(scenario);
    }
}
