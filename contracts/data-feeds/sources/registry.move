/// The registry module stores all the state associated with data feeds.
module chainlink_data_feeds::registry {
    use std::string;
    use std::option;
    use std::vector;
    
    use sui::object;
    use sui::table::{Self, Table};
    use sui::tx_context;
    use sui::transfer;
    use sui::event;
    
    use chainlink_platform::storage;
    use chainlink_platform::vector_utils;
    
    // Using package visibility instead of friend
    // friend chainlink_data_feeds::router;
    
    // Constants
    // Unused constant
    // const APP_OBJECT_SEED: vector<u8> = b"REGISTRY";
    
    // Schema types
    const SCHEMA_V3: u16 = 3;
    const SCHEMA_V4: u16 = 4;
    
    // Error codes
    const E_NOT_OWNER: u64 = 1;
    const E_DUPLICATE_ELEMENTS: u64 = 2;
    const E_FEED_EXISTS: u64 = 3;
    const E_FEED_NOT_CONFIGURED: u64 = 4;
    // Unused constant
    // const E_CONFIG_NOT_CONFIGURED: u64 = 5;
    const E_UNEQUAL_ARRAY_LENGTHS: u64 = 6;
    const E_INVALID_REPORT: u64 = 7;
    const E_UNAUTHORIZED_WORKFLOW_NAME: u64 = 8;
    const E_UNAUTHORIZED_WORKFLOW_OWNER: u64 = 9;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 10;
    const E_NOT_PROPOSED_OWNER: u64 = 11;
    const E_EMPTY_WORKFLOW_OWNERS: u64 = 12;
    
    // Capability for authorizing sensitive operations
    public struct AdminCap has key, store {
        id: UID
    }
    
    public struct Registry has key {
        id: UID,
        owner_address: address,
        pending_owner_address: address,
        feeds: Table<vector<u8>, Feed>,
        allowed_workflow_owners: vector<vector<u8>>,
        allowed_workflow_names: vector<vector<u8>>
    }
    
    public struct Feed has store, copy, drop {
        description: String,
        config_id: vector<u8>,
        benchmark: u256,
        report: vector<u8>,
        observation_timestamp: u256
    }
    
    public struct Benchmark has store, copy, drop {
        benchmark: u256,
        observation_timestamp: u256
    }
    
    public struct Report has store, copy, drop {
        report: vector<u8>,
        observation_timestamp: u256
    }
    
    public struct FeedMetadata has store, copy, drop {
        description: String,
        config_id: vector<u8>
    }
    
    public struct WorkflowConfig has copy, drop {
        allowed_workflow_owners: vector<vector<u8>>,
        allowed_workflow_names: vector<vector<u8>>
    }
    
    public struct FeedConfig has copy, drop {
        feed_id: vector<u8>,
        feed: Feed
    }
    
    // Events
    public struct FeedDescriptionUpdated has copy, drop {
        feed_id: vector<u8>,
        description: String
    }
    
    public struct FeedRemoved has copy, drop {
        feed_id: vector<u8>
    }
    
    public struct FeedSet has copy, drop {
        feed_id: vector<u8>,
        description: String,
        config_id: vector<u8>
    }
    
    public struct FeedUpdated has copy, drop {
        feed_id: vector<u8>,
        timestamp: u256,
        benchmark: u256,
        report: vector<u8>
    }
    
    public struct StaleReport has copy, drop {
        feed_id: vector<u8>,
        latest_timestamp: u256,
        report_timestamp: u256
    }
    
    public struct OwnershipTransferRequested has copy, drop {
        from: address,
        to: address
    }
    
    public struct OwnershipTransferred has copy, drop {
        from: address,
        to: address
    }
    
    // One-time initialization function
    fun init(ctx: &mut TxContext) {
        // Create the registry object
        let registry = Registry {
            id: object::new(ctx),
            owner_address: tx_context::sender(ctx),
            pending_owner_address: @0x0,
            feeds: table::new(ctx),
            allowed_workflow_names: vector::empty(),
            allowed_workflow_owners: vector::empty()
        };
        
        // Create admin capability
        let admin_cap = AdminCap {
            id: object::new(ctx)
        };
        
        // Share the registry object
        transfer::share_object(registry);
        
        // Transfer the admin capability to the sender
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }
    
    // Helper functions
    fun assert_is_owner(registry: &Registry, target_address: address) {
        assert!(
            registry.owner_address == target_address,
            E_NOT_OWNER
        );
    }
    
    fun assert_no_duplicates<T: copy + drop>(a: &vector<T>) {
        let len = vector::length(a);
        let mut i = 0;
        while (i < len) {
            let mut j = i + 1;
            while (j < len) {
                assert!(
                    *vector::borrow(a, i) != *vector::borrow(a, j),
                    E_DUPLICATE_ELEMENTS
                );
                j = j + 1;
            };
            i = i + 1;
        }
    }
    
    // Public entry functions
    public entry fun set_feeds(
        _admin_cap: &AdminCap,
        registry: &mut Registry,
        feed_ids: vector<vector<u8>>,
        descriptions: vector<String>,
        config_id: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert_is_owner(registry, tx_context::sender(ctx));
        set_feeds_internal(registry, feed_ids, descriptions, config_id);
    }
    
    public(package) fun set_feeds_unchecked(
        registry: &mut Registry,
        feed_ids: vector<vector<u8>>,
        descriptions: vector<String>,
        config_id: vector<u8>
    ) {
        set_feeds_internal(registry, feed_ids, descriptions, config_id);
    }
    
    fun set_feeds_internal(
        registry: &mut Registry,
        feed_ids: vector<vector<u8>>,
        descriptions: vector<String>,
        config_id: vector<u8>
    ) {
        assert_no_duplicates(&feed_ids);
        
        assert!(
            vector::length(&feed_ids) == vector::length(&descriptions),
            E_UNEQUAL_ARRAY_LENGTHS
        );
        
        let mut i = 0;
        let len = vector::length(&feed_ids);
        
        while (i < len) {
            let feed_id = *vector::borrow(&feed_ids, i);
            let description = *vector::borrow(&descriptions, i);
            
            assert!(
                !table::contains(&registry.feeds, feed_id),
                E_FEED_EXISTS
            );
            
            let feed = Feed {
                description,
                config_id,
                benchmark: 0,
                report: vector::empty(),
                observation_timestamp: 0
            };
            
            table::add(&mut registry.feeds, feed_id, feed);
            
            event::emit(
                FeedSet { feed_id, description, config_id }
            );
            
            i = i + 1;
        }
    }
    
    public entry fun remove_feeds(
        _admin_cap: &AdminCap,
        registry: &mut Registry,
        feed_ids: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        assert_is_owner(registry, tx_context::sender(ctx));
        
        assert_no_duplicates(&feed_ids);
        
        let mut i = 0;
        let len = vector::length(&feed_ids);
        
        while (i < len) {
            let feed_id = *vector::borrow(&feed_ids, i);
            
            assert!(
                table::contains(&registry.feeds, feed_id),
                E_FEED_NOT_CONFIGURED
            );
            
            table::remove(&mut registry.feeds, feed_id);
            
            event::emit(FeedRemoved { feed_id });
            
            i = i + 1;
        }
    }
    
    public entry fun update_descriptions(
        _admin_cap: &AdminCap,
        registry: &mut Registry,
        feed_ids: vector<vector<u8>>,
        descriptions: vector<String>,
        ctx: &mut TxContext
    ) {
        assert_is_owner(registry, tx_context::sender(ctx));
        
        assert!(
            vector::length(&feed_ids) == vector::length(&descriptions),
            E_UNEQUAL_ARRAY_LENGTHS
        );
        
        let mut i = 0;
        let len = vector::length(&feed_ids);
        
        while (i < len) {
            let feed_id = *vector::borrow(&feed_ids, i);
            let description = *vector::borrow(&descriptions, i);
            
            assert!(
                table::contains(&registry.feeds, feed_id),
                E_FEED_NOT_CONFIGURED
            );
            
            let feed = table::borrow_mut(&mut registry.feeds, feed_id);
            feed.description = description;
            
            event::emit(
                FeedDescriptionUpdated { feed_id, description }
            );
            
            i = i + 1;
        }
    }
    
    // Conversion functions for big-endian values
    fun to_u16be(data: vector<u8>): u16 {
        // Simplified implementation for big-endian to little-endian conversion
        let mut result: u16 = 0;
        let len = vector::length(&data);
        
        if (len > 0) {
            let mut i = 0;
            while (i < len && i < 2) {
                result = result | ((*vector::borrow(&data, len - i - 1) as u16) << ((i * 8) as u8));
                i = i + 1;
            }
        };
        
        result
    }
    
    fun to_u32be(data: vector<u8>): u32 {
        // Simplified implementation for big-endian to little-endian conversion
        let mut result: u32 = 0;
        let len = vector::length(&data);
        
        if (len > 0) {
            let mut i = 0;
            while (i < len && i < 4) {
                result = result | ((*vector::borrow(&data, len - i - 1) as u32) << ((i * 8) as u8));
                i = i + 1;
            }
        };
        
        result
    }
    
    fun to_u256be(data: vector<u8>): u256 {
        // Simplified implementation for big-endian to little-endian conversion
        let mut result: u256 = 0;
        let len = vector::length(&data);
        
        if (len > 0) {
            let mut i = 0;
            while (i < len && i < 32) {
                result = result | ((*vector::borrow(&data, len - i - 1) as u256) << ((i * 8) as u8));
                i = i + 1;
            }
        };
        
        result
    }
    
    // Proof type for the dispatch engine
    public struct OnReceive has drop {}
    
    #[allow(unused_function)]
    fun new_proof(): OnReceive {
        OnReceive {}
    }
    
    // Platform receiver function interface
    public fun on_report(registry: &mut Registry): Option<u128> {
        // TODO: Implement storage::retrieve in the platform module
        // For now, we'll use a placeholder implementation
        let metadata = vector::empty<u8>();
        let data = vector::empty<u8>();
        
        // This is a placeholder - in a real implementation, we would retrieve data from storage
        // let (metadata, data) = storage::retrieve(new_proof());
        
        let parsed_metadata = storage::parse_report_metadata(metadata);
        
        let workflow_owner = storage::get_report_metadata_workflow_owner(&parsed_metadata);
        assert!(
            vector::contains(&registry.allowed_workflow_owners, &workflow_owner),
            E_UNAUTHORIZED_WORKFLOW_OWNER
        );
        
        let workflow_name = storage::get_report_metadata_workflow_name(&parsed_metadata);
        assert!(
            vector::is_empty(&registry.allowed_workflow_names)
                || vector::contains(&registry.allowed_workflow_names, &workflow_name),
            E_UNAUTHORIZED_WORKFLOW_NAME
        );
        
        let (feed_ids, reports) = parse_raw_report(data);
        
        let mut i = 0;
        let len = vector::length(&feed_ids);
        
        while (i < len) {
            let feed_id = *vector::borrow(&feed_ids, i);
            let report = *vector::borrow(&reports, i);
            
            perform_update(registry, feed_id, report);
            
            i = i + 1;
        };
        
        option::none()
    }
    
    public entry fun set_workflow_config(
        _admin_cap: &AdminCap,
        registry: &mut Registry,
        allowed_workflow_owners: vector<vector<u8>>,
        allowed_workflow_names: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        assert_is_owner(registry, tx_context::sender(ctx));
        assert!(
            !vector::is_empty(&allowed_workflow_owners),
            E_EMPTY_WORKFLOW_OWNERS
        );
        
        registry.allowed_workflow_owners = allowed_workflow_owners;
        registry.allowed_workflow_names = allowed_workflow_names;
    }
    
    // View functions
    public fun get_workflow_config(registry: &Registry): WorkflowConfig {
        WorkflowConfig {
            allowed_workflow_owners: registry.allowed_workflow_owners,
            allowed_workflow_names: registry.allowed_workflow_names
        }
    }
    
    public fun get_feeds(_registry: &Registry): vector<FeedConfig> {
        let feed_configs = vector::empty<FeedConfig>();
        
        // In Sui, we don't have a direct table::keys function
        // We would need to implement a custom solution or modify the data structure
        // For now, this is a placeholder implementation
        
        // TODO: Implement a way to iterate through all keys in the table
        // This would require either:
        // 1. Maintaining a separate vector of keys
        // 2. Using a different data structure like LinkedTable
        // 3. Implementing a custom solution
        
        feed_configs
    }
    
    // Parse ETH ABI encoded raw data into multiple reports
    fun parse_raw_report(data: vector<u8>): (vector<vector<u8>>, vector<vector<u8>>) {
        let mut offset = 0;
        assert!(
            to_u256be(vector_utils::slice(&data, offset, offset + 32)) == 32,
            32
        );
        offset = offset + 32;
        
        let count = to_u256be(vector_utils::slice(&data, offset, offset + 32));
        offset = offset + 32;
        
        let mut i = 0;
        while (i < count) {
            // skip len * offsets table
            offset = offset + 32;
            i = i + 1;
        };
        
        let mut feed_ids = vector::empty<vector<u8>>();
        let mut reports = vector::empty<vector<u8>>();
        
        i = 0;
        while (i < count) {
            let feed_id = vector_utils::slice(&data, offset, offset + 32);
            vector::push_back(&mut feed_ids, feed_id);
            offset = offset + 32;
            
            assert!(
                to_u256be(vector_utils::slice(&data, offset, offset + 32)) == 64,
                64
            );
            offset = offset + 32;
            
            let len = (to_u256be(vector_utils::slice(&data, offset, offset + 32)) as u64);
            offset = offset + 32;
            
            let report = vector_utils::slice(&data, offset, offset + len);
            vector::push_back(&mut reports, report);
            offset = offset + len;
            
            i = i + 1;
        };
        
        (feed_ids, reports)
    }
    
    fun perform_update(
        registry: &mut Registry, feed_id: vector<u8>, report_data: vector<u8>
    ) {
        assert!(
            table::contains(&registry.feeds, feed_id),
            E_FEED_NOT_CONFIGURED
        );
        let feed = table::borrow_mut(&mut registry.feeds, feed_id);
        
        let report_feed_id = vector_utils::slice(&report_data, 0, 32);
        // schema is based on first two bytes of the feed id
        let schema = to_u16be(vector_utils::slice(&report_feed_id, 0, 2));
        
        let observation_timestamp: u256;
        let benchmark_price: u256;
        if (schema == SCHEMA_V3 || schema == SCHEMA_V4) {
            // offsets are the same for timestamp and benchmark in v3 and v4.
            observation_timestamp =
                (to_u32be(vector_utils::slice(&report_data, 3 * 32 - 4, 3 * 32)) as u256);
            // NOTE: sui has no signed integer types, so can't parse as i196, this is a raw representation
            benchmark_price = to_u256be(vector_utils::slice(&report_data, 6 * 32, 7 * 32));
        } else {
            abort E_INVALID_REPORT
        };
        
        if (feed.observation_timestamp >= observation_timestamp) {
            event::emit(
                StaleReport {
                    feed_id,
                    latest_timestamp: feed.observation_timestamp,
                    report_timestamp: observation_timestamp
                }
            );
            return
        };
        
        feed.observation_timestamp = observation_timestamp;
        feed.benchmark = benchmark_price;
        feed.report = report_data;
        
        event::emit(
            FeedUpdated {
                feed_id,
                timestamp: observation_timestamp,
                benchmark: benchmark_price,
                report: report_data
            }
        );
    }
    
    // Getters
    public fun get_benchmarks(
        _admin_cap: &AdminCap,
        registry: &Registry,
        feed_ids: vector<vector<u8>>,
        ctx: &TxContext
    ): vector<Benchmark> {
        assert_is_owner(registry, tx_context::sender(ctx));
        get_benchmarks_internal(registry, feed_ids)
    }
    
    public(package) fun get_benchmarks_unchecked(
        registry: &Registry,
        feed_ids: vector<vector<u8>>
    ): vector<Benchmark> {
        get_benchmarks_internal(registry, feed_ids)
    }
    
    fun get_benchmarks_internal(
        registry: &Registry, feed_ids: vector<vector<u8>>
    ): vector<Benchmark> {
        let mut results = vector::empty<Benchmark>();
        
        let mut i = 0;
        let len = vector::length(&feed_ids);
        
        while (i < len) {
            let feed_id = *vector::borrow(&feed_ids, i);
            
            assert!(
                table::contains(&registry.feeds, feed_id),
                E_FEED_NOT_CONFIGURED
            );
            
            let feed = table::borrow(&registry.feeds, feed_id);
            
            vector::push_back(
                &mut results,
                Benchmark {
                    benchmark: feed.benchmark,
                    observation_timestamp: feed.observation_timestamp
                }
            );
            
            i = i + 1;
        };
        
        results
    }
    
    public fun get_reports(
        _admin_cap: &AdminCap,
        registry: &Registry,
        feed_ids: vector<vector<u8>>,
        ctx: &TxContext
    ): vector<Report> {
        assert_is_owner(registry, tx_context::sender(ctx));
        get_reports_internal(registry, feed_ids)
    }
    
    public(package) fun get_reports_unchecked(
        registry: &Registry,
        feed_ids: vector<vector<u8>>
    ): vector<Report> {
        get_reports_internal(registry, feed_ids)
    }
    
    fun get_reports_internal(
        registry: &Registry, feed_ids: vector<vector<u8>>
    ): vector<Report> {
        let mut results = vector::empty<Report>();
        
        let mut i = 0;
        let len = vector::length(&feed_ids);
        
        while (i < len) {
            let feed_id = *vector::borrow(&feed_ids, i);
            
            assert!(
                table::contains(&registry.feeds, feed_id),
                E_FEED_NOT_CONFIGURED
            );
            
            let feed = table::borrow(&registry.feeds, feed_id);
            
            vector::push_back(
                &mut results,
                Report {
                    report: feed.report,
                    observation_timestamp: feed.observation_timestamp
                }
            );
            
            i = i + 1;
        };
        
        results
    }
    
    public fun get_feed_metadata(
        registry: &Registry,
        feed_ids: vector<vector<u8>>
    ): vector<FeedMetadata> {
        let mut results = vector::empty<FeedMetadata>();
        
        let mut i = 0;
        let len = vector::length(&feed_ids);
        
        while (i < len) {
            let feed_id = *vector::borrow(&feed_ids, i);
            
            assert!(
                table::contains(&registry.feeds, feed_id),
                E_FEED_NOT_CONFIGURED
            );
            
            let feed = table::borrow(&registry.feeds, feed_id);
            
            vector::push_back(
                &mut results,
                FeedMetadata { 
                    description: feed.description, 
                    config_id: feed.config_id 
                }
            );
            
            i = i + 1;
        };
        
        results
    }
    
    // Ownership functions
    public fun get_owner(registry: &Registry): address {
        registry.owner_address
    }
    
    public entry fun transfer_ownership(
        _admin_cap: &AdminCap,
        registry: &mut Registry,
        to: address,
        ctx: &mut TxContext
    ) {
        assert_is_owner(registry, tx_context::sender(ctx));
        assert!(
            registry.owner_address != to,
            E_CANNOT_TRANSFER_TO_SELF
        );
        
        registry.pending_owner_address = to;
        
        event::emit(OwnershipTransferRequested { from: registry.owner_address, to });
    }
    
    public entry fun accept_ownership(
        registry: &mut Registry,
        ctx: &mut TxContext
    ) {
        assert!(
            registry.pending_owner_address == tx_context::sender(ctx),
            E_NOT_PROPOSED_OWNER
        );
        
        let old_owner_address = registry.owner_address;
        registry.owner_address = registry.pending_owner_address;
        registry.pending_owner_address = @0x0;
        
        event::emit(
            OwnershipTransferred { from: old_owner_address, to: registry.owner_address }
        );
    }
    
    // Struct accessors
    public fun get_benchmark_value(result: &Benchmark): u256 {
        result.benchmark
    }
    
    public fun get_benchmark_timestamp(result: &Benchmark): u256 {
        result.observation_timestamp
    }
    
    public fun get_report_value(result: &Report): vector<u8> {
        result.report
    }
    
    public fun get_report_timestamp(result: &Report): u256 {
        result.observation_timestamp
    }
    
    public fun get_feed_metadata_description(result: &FeedMetadata): String {
        result.description
    }
    
    public fun get_feed_metadata_config_id(result: &FeedMetadata): vector<u8> {
        result.config_id
    }
    
    // Test functions
    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx);
    }
}
