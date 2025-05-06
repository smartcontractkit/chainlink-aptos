#[test_only]
module chainlink_ccip::ccip_tests {
    use std::string;
    use std::vector;
    
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::test_utils;
    
    use chainlink_ccip::allowlist;
    use chainlink_ccip::ownable;
    use chainlink_ccip::state_object::{Self, StateObject};
    use chainlink_ccip::auth::{Self, AdminCap};
    
    #[test]
    fun test_allowlist_basic() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            // Initialize with empty allowlist
            let state = allowlist::new(vector::empty());
            
            // Check that allowlist is disabled
            assert!(!allowlist::get_allowlist_enabled(&state), 0);
            
            // Enable allowlist
            allowlist::set_allowlist_enabled(&mut state, true);
            
            // Add addresses
            let adds = vector[@0x1, @0x2];
            allowlist::apply_allowlist_updates(&mut state, vector::empty(), adds);
            
            // Check that addresses are allowed
            assert!(allowlist::is_allowed(&state, @0x1), 0);
            assert!(allowlist::is_allowed(&state, @0x2), 0);
            
            // Remove an address
            let removes = vector[@0x1];
            allowlist::apply_allowlist_updates(&mut state, removes, vector::empty());
            
            // Check that address is no longer allowed
            assert!(!allowlist::is_allowed(&state, @0x1), 0);
            assert!(allowlist::is_allowed(&state, @0x2), 0);
            
            // Cleanup
            allowlist::destroy_allowlist(state);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    fun test_ownable_basic() {
        let owner = @0xA;
        let new_owner = @0xB;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            // Initialize ownable state
            let state = ownable::new(owner);
            
            // Check owner
            assert!(ownable::owner(&state) == owner, 0);
            
            // Transfer ownership
            ownable::transfer_ownership(owner, &mut state, new_owner);
            
            // Check pending owner
            assert!(ownable::pending_owner(&state) == new_owner, 0);
            
            // Accept ownership
            ownable::accept_ownership(new_owner, &mut state);
            
            // Check new owner
            assert!(ownable::owner(&state) == new_owner, 0);
            assert!(ownable::pending_owner(&state) == @0x0, 0);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    #[expected_failure(abort_code = 0x1, location = chainlink_ccip::ownable)]
    fun test_ownable_not_owner() {
        let owner = @0xA;
        let not_owner = @0xB;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            // Initialize ownable state
            let state = ownable::new(owner);
            
            // Try to transfer ownership as non-owner (should fail)
            ownable::transfer_ownership(not_owner, &mut state, not_owner);
        };
        
        ts::end(scenario);
    }
    
    // Additional tests would be added for auth module and other components
}
