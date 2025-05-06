#[test_only]
module chainlink_platform::platform_tests {
    use std::vector;
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::test_utils;
    
    use chainlink_platform::forwarder::{Self, AdminCap, State};
    
    #[test]
    fun test_basic_setup() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            // Initialize the modules
            test_utils::assert_eq(ts::ctx(&mut scenario), nil);
        };
        
        // Test checking config operations
        ts::next_tx(&mut scenario, owner);
        {
            // Get the admin cap and state objects
            let admin_cap = ts::take_from_sender<AdminCap>(&scenario);
            let state = ts::take_shared<State>(&scenario);
            
            // Test that owner is correctly set
            assert!(forwarder::get_owner(&state) == owner, 0);
            
            // Return objects
            ts::return_to_sender(&scenario, admin_cap);
            ts::return_shared(state);
        };
        
        ts::end(scenario);
    }
}
