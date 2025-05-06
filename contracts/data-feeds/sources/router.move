/// The router module provides an interface to the registry module.
module chainlink_data_feeds::router {
    use std::string::String;
    use std::vector;
    
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    
    use chainlink_data_feeds::registry::{Self, Benchmark, Report};
    
    // Constants
    const APP_OBJECT_SEED: vector<u8> = b"ROUTER";
    
    // Error codes
    const E_NOT_OWNER: u64 = 0;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 1;
    const E_NOT_PROPOSED_OWNER: u64 = 2;
    
    // Capability for authorizing sensitive operations
    struct AdminCap has key, store {
        id: UID
    }
    
    struct Router has key {
        id: UID,
        owner_address: address,
        pending_owner_address: address
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
    
    // Helper functions
    fun assert_is_owner(router: &Router, target_address: address) {
        assert!(
            router.owner_address == target_address, 
            E_NOT_OWNER
        );
    }
    
    // One-time initialization function
    fun init(ctx: &mut TxContext) {
        // Create the router object
        let router = Router {
            id: object::new(ctx),
            owner_address: tx_context::sender(ctx),
            pending_owner_address: @0x0
        };
        
        // Create admin capability
        let admin_cap = AdminCap {
            id: object::new(ctx)
        };
        
        // Share the router object
        transfer::share_object(router);
        
        // Transfer the admin capability to the sender
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }
    
    // Public entry functions
    public fun get_benchmarks(
        admin_cap: &AdminCap,
        router: &Router,
        registry: &registry::Registry,
        feed_ids: vector<vector<u8>>,
        _billing_data: vector<u8>,
        ctx: &TxContext
    ): vector<Benchmark> {
        assert_is_owner(router, tx_context::sender(ctx));
        
        registry::get_benchmarks_unchecked(registry, feed_ids)
    }
    
    public fun get_reports(
        admin_cap: &AdminCap,
        router: &Router,
        registry: &registry::Registry,
        feed_ids: vector<vector<u8>>,
        _billing_data: vector<u8>,
        ctx: &TxContext
    ): vector<Report> {
        assert_is_owner(router, tx_context::sender(ctx));
        
        registry::get_reports_unchecked(registry, feed_ids)
    }
    
    public fun get_descriptions(
        router: &Router,
        registry: &registry::Registry,
        feed_ids: vector<vector<u8>>
    ): vector<String> {
        let results = registry::get_feed_metadata(registry, feed_ids);
        vector::map(
            results, |metadata| registry::get_feed_metadata_description(&metadata)
        )
    }
    
    public entry fun configure_feeds(
        admin_cap: &AdminCap,
        router: &Router,
        registry: &mut registry::Registry,
        feed_ids: vector<vector<u8>>,
        descriptions: vector<String>,
        config_id: vector<u8>,
        _fee_config_id: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert_is_owner(router, tx_context::sender(ctx));
        
        registry::set_feeds_unchecked(registry, feed_ids, descriptions, config_id);
    }
    
    // Ownership functions
    public fun get_owner(router: &Router): address {
        router.owner_address
    }
    
    public entry fun transfer_ownership(
        admin_cap: &AdminCap,
        router: &mut Router,
        to: address,
        ctx: &mut TxContext
    ) {
        assert_is_owner(router, tx_context::sender(ctx));
        assert!(
            router.owner_address != to,
            E_CANNOT_TRANSFER_TO_SELF
        );
        
        router.pending_owner_address = to;
        
        event::emit(OwnershipTransferRequested { from: router.owner_address, to });
    }
    
    public entry fun accept_ownership(
        router: &mut Router,
        ctx: &mut TxContext
    ) {
        assert!(
            router.pending_owner_address == tx_context::sender(ctx),
            E_NOT_PROPOSED_OWNER
        );
        
        let old_owner_address = router.owner_address;
        router.owner_address = router.pending_owner_address;
        router.pending_owner_address = @0x0;
        
        event::emit(
            OwnershipTransferred { from: old_owner_address, to: router.owner_address }
        );
    }
    
    // Test functions would be added in a separate test module
}
