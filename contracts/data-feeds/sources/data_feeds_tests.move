#[test_only]
module chainlink_data_feeds::data_feeds_tests {
    use std::string;
    use std::vector;
    
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::test_utils;
    
    use chainlink_data_feeds::registry::{Self, Registry, AdminCap as RegistryAdminCap};
    use chainlink_data_feeds::router::{Self, Router, AdminCap as RouterAdminCap};
    
    #[test]
    fun test_basic_setup() {
        let owner = @0xA;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            // Initialize the modules
            registry::init(ts::ctx(&mut scenario));
            router::init(ts::ctx(&mut scenario));
        };
        
        // Test registry operations
        ts::next_tx(&mut scenario, owner);
        {
            // Get the admin cap and registry objects
            let registry_admin_cap = ts::take_from_sender<RegistryAdminCap>(&scenario);
            let registry = ts::take_shared<Registry>(&scenario);
            
            // Test that owner is correctly set
            assert!(registry::get_owner(&registry) == owner, 0);
            
            // Return objects
            ts::return_to_sender(&scenario, registry_admin_cap);
            ts::return_shared(registry);
        };
        
        // Test router operations
        ts::next_tx(&mut scenario, owner);
        {
            // Get the admin cap and router objects
            let router_admin_cap = ts::take_from_sender<RouterAdminCap>(&scenario);
            let router = ts::take_shared<Router>(&scenario);
            
            // Test that owner is correctly set
            assert!(router::get_owner(&router) == owner, 0);
            
            // Return objects
            ts::return_to_sender(&scenario, router_admin_cap);
            ts::return_shared(router);
        };
        
        // Test feed configuration
        ts::next_tx(&mut scenario, owner);
        {
            // Get the admin caps and objects
            let registry_admin_cap = ts::take_from_sender<RegistryAdminCap>(&scenario);
            let router_admin_cap = ts::take_from_sender<RouterAdminCap>(&scenario);
            let registry = ts::take_shared<Registry>(&scenario);
            let router = ts::take_shared<Router>(&scenario);
            
            // Configure a feed
            let feed_ids = vector[b"test_feed_id"];
            let descriptions = vector[string::utf8(b"Test Feed")];
            let config_id = b"config_id";
            
            registry::set_feeds(
                &registry_admin_cap,
                &mut registry,
                feed_ids,
                descriptions,
                config_id,
                ts::ctx(&mut scenario)
            );
            
            // Get feed metadata
            let metadata = registry::get_feed_metadata(&registry, feed_ids);
            assert!(vector::length(&metadata) == 1, 0);
            
            // Verify description
            let feed_metadata = vector::borrow(&metadata, 0);
            assert!(
                registry::get_feed_metadata_description(feed_metadata) == 
                string::utf8(b"Test Feed"),
                0
            );
            
            // Return objects
            ts::return_to_sender(&scenario, registry_admin_cap);
            ts::return_to_sender(&scenario, router_admin_cap);
            ts::return_shared(registry);
            ts::return_shared(router);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    fun test_ownership_transfer() {
        let owner = @0xA;
        let new_owner = @0xB;
        
        // Test setup
        let scenario = ts::begin(owner);
        {
            // Initialize the modules
            registry::init(ts::ctx(&mut scenario));
            router::init(ts::ctx(&mut scenario));
        };
        
        // Test registry ownership transfer
        ts::next_tx(&mut scenario, owner);
        {
            // Get the admin cap and registry objects
            let registry_admin_cap = ts::take_from_sender<RegistryAdminCap>(&scenario);
            let registry = ts::take_shared<Registry>(&scenario);
            
            // Transfer ownership
            registry::transfer_ownership(
                &registry_admin_cap,
                &mut registry,
                new_owner,
                ts::ctx(&mut scenario)
            );
            
            // Return objects
            ts::return_to_sender(&scenario, registry_admin_cap);
            ts::return_shared(registry);
        };
        
        // Accept ownership
        ts::next_tx(&mut scenario, new_owner);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            registry::accept_ownership(
                &mut registry,
                ts::ctx(&mut scenario)
            );
            
            // Verify new owner
            assert!(registry::get_owner(&registry) == new_owner, 0);
            
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }
}
