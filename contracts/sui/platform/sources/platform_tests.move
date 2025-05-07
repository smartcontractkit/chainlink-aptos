#[test_only]
module chainlink_platform::platform_tests {
    use sui::test_scenario::{Self as ts};
    
    use chainlink_platform::forwarder::{Self, AdminCap, State};
    use chainlink_platform::vector_utils;
    
    #[test]
    fun test_basic_setup() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        
        // Initialize the forwarder module explicitly for testing
        ts::next_tx(&mut scenario, owner);
        {
            forwarder::init_for_testing(ts::ctx(&mut scenario));
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
    
    #[test]
    fun test_vector_utils() {
        // Test vector slice
        let v = vector[1, 2, 3, 4, 5];
        assert!(vector_utils::slice(&v, 1, 4) == vector[2, 3, 4], 0);
        
        // Test to_u16_be
        let bytes = vector[0x12, 0x34];
        assert!(vector_utils::to_u16_be(&bytes) == 0x1234, 0);
        
        // Test to_u32_be
        let bytes = vector[0x12, 0x34, 0x56, 0x78];
        assert!(vector_utils::to_u32_be(&bytes) == 0x12345678, 0);
    }
}
