/// The router module provides an interface to the registry module.
module chainlink_data_feeds::router {
    use std::string;
    use std::vector;
    
    use sui::object;
    use sui::tx_context;
    use sui::transfer;
    use sui::event;
    
    use chainlink_data_feeds::registry::{Self, Benchmark, Report};
    
    // Constants
    // Unused constant
    // const APP_OBJECT_SEED: vector<u8> = b"ROUTER";
    
    // Error codes
    const E_NOT_OWNER: u64 = 0;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 1;
    const E_NOT_PROPOSED_OWNER: u64 = 2;
    
    // Capability for authorizing sensitive operations
    public struct AdminCap has key, store {
        id: UID
    }
    
    public struct Router has key {
        id: UID,
        owner_address: address,
        pending_owner_address: address
    }
    
    // Events
    public struct OwnershipTransferRequested has copy, drop {
        from: address,
        to: address
    }
    
    public struct OwnershipTransferred has copy, drop {
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
        _admin_cap: &AdminCap,
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
        _admin_cap: &AdminCap,
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
        _router: &Router,
        registry: &registry::Registry,
        feed_ids: vector<vector<u8>>
    ): vector<String> {
        let results = registry::get_feed_metadata(registry, feed_ids);
        vector::map!(
            results, |metadata| registry::get_feed_metadata_description(&metadata)
        )
    }
    
    public entry fun configure_feeds(
        _admin_cap: &AdminCap,
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
        _admin_cap: &AdminCap,
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
    
    // Test functions
    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx);
    }
}
