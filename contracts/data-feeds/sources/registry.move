module data_feeds::registry {
    use std::error;
    use std::event;
    use std::signer;
    use std::simple_map::{Self, SimpleMap};
    use std::string::String;
    use std::vector;

    use aptos_framework::object::{Self};

    const APP_OBJECT_SEED: vector<u8> = b"REGISTRY";

    // TODO: figure out link_address, router, verifier_proxy
    struct Registry has key, store, drop {
        owner_address: address,
        router_address: address,

        feeds: SimpleMap<vector<u8>, Feed>,
        configs: SimpleMap<vector<u8>, Config>,
        // upkeep to feed ids
        upkeep_feed_id_set: SimpleMap<address, vector<vector<u8>>>
    }

    struct Feed has key, store, drop {
        description: String,
        config_id: vector<u8>,
        upkeep: address,
        upkeep_requested: bool,
        // TODO: int256 in solidity contract
        benchmark: u256,
        report: vector<u8>,
        observation_timestamp: u256,
    }

    struct Config has key, store, drop {
        deviation_threshold: u256,

        // TODO: shrink down to u64?
        staleness_seconds: u256,
    }

    // TODO: are tuples cleaner than requiring getters?
    struct BenchmarkResult has store, drop {
        benchmark: u256,
        observation_timestamp: u256
    }

    struct ReportResult has store, drop {
        report: vector<u8>,
        observation_timestamp: u256,
    }

    struct FeedMetadataResult has store, drop, key {
        description: String,
        config_id: vector<u8>,
        deviation_threshold: u256,
        staleness_seconds: u256,
        upkeep_requested: bool,
    }

    struct FeedConfigResult has store, drop {
        deviation_threshold: u256,
        staleness_seconds: u256,
    }

    #[event]
    struct Initialized has drop, store {
        address: address,
    }

    #[event]
    struct FeedConfigIdUpdated has drop, store {
        feed_id: vector<u8>,
        config_id: vector<u8>,
    }

    #[event]
    struct FeedConfigSet has drop, store {
        config_id: vector<u8>,
        deviation_threshold: u256,
        staleness_seconds: u256,
    }

    #[event]
    struct FeedDescriptionUpdated has drop, store {
        feed_id: vector<u8>,
        description: String
    }

    #[event]
    struct FeedRemoved has drop, store {
        feed_id: vector<u8>,
    }

    #[event]
    struct FeedSet has drop, store {
        feed_id: vector<u8>,
        description: String,
        config_id: vector<u8>,
        upkeep: address
    }

    #[event]
    struct FeedUpdated has drop, store {
        feed_id: vector<u8>,
        timestamp: u256,
        benchmark: u256,
        report: vector<u8>
    }

    #[event]
    struct StaleReport has drop, store {
        feed_id: vector<u8>,
        latest_timestamp: u256,
        report_timestamp: u256,
    }

    #[event]
    struct UnauthorizedUpkeep has drop, store {
        feed_id: vector<u8>,
        upkeep: address,
        sender: address,
    }

    #[event]
    struct UpkeepRequested has drop, store {
        feed_id: vector<u8>,
    }

    #[event]
    struct UpkeepUpdated has drop, store {
        feed_id: vector<u8>,
        upkeep: address,
    }

    // Errors
    const ENOT_OWNER: u64 = 1;
    const EDUPLICATE_ELEMENTS: u64 = 2;
    const EFEED_EXISTS: u64 = 3;
    const EFEED_NOT_CONFIGURED: u64 = 4;
    const ECONFIG_NOT_CONFIGURED: u64 = 5;
    const EINVALID_UPKEEP: u64 = 6;
    const EUNAUTHORIZED_DATA_FETCH: u64 = 7;
    const EUNAUTHORIZED_ROUTER_OPERATION: u64 = 8;
    const EUNEQUAL_ARRAY_LENGTHS: u64 = 9;
    const EINVALID_REPORT: u64 = 10;

    // Schema types
    const BLOCK_PREMIUM_SCHEMA: u16 = 1;
    const BASIC_SCHEMA: u16 = 2;
    const PREMIUM_SCHEMA: u16 = 3;

    fun assert_is_owner(registry: &Registry, target_address: address) {
        assert!(registry.owner_address == target_address, error::invalid_argument(ENOT_OWNER));
    }

    fun assert_is_owner_or_router(registry: &Registry, target_address: address) {
        assert!(registry.owner_address == target_address || registry.router_address == target_address, error::invalid_argument(EUNAUTHORIZED_ROUTER_OPERATION));
    }

    fun assert_authorized_data_fetch(registry: &Registry, target_address: address, feed_ids: &vector<vector<u8>>) {
        if (registry.owner_address == target_address || registry.router_address == target_address) {
            return
        };

        assert!(simple_map::contains_key(&registry.upkeep_feed_id_set, &target_address), error::invalid_argument(EUNAUTHORIZED_DATA_FETCH));

        let upkeep_feed_ids = simple_map::borrow(&registry.upkeep_feed_id_set, &target_address);
        vector::for_each_ref(feed_ids, |feed_id| {
            assert!(vector::contains(upkeep_feed_ids, feed_id), error::invalid_argument(EUNAUTHORIZED_DATA_FETCH));
        });
    }

    fun assert_no_duplicates<T>(a: &vector<T>) {
        let len = vector::length(a);
        for (i in 0..len) {
            for (j in (i + 1)..len) {
                assert!(vector::borrow(a, i) != vector::borrow(a, j), error::invalid_argument(EDUPLICATE_ELEMENTS));
            }
        }
    }

    fun init_module(account: &signer) {
        let constructor_ref = object::create_named_object(
            account,
            APP_OBJECT_SEED,
        );
        let _object_address = object::address_from_constructor_ref(&constructor_ref);

        // Store an ExtendRef alongside the object.
        let _extend_ref = object::generate_extend_ref(&constructor_ref);
        let object_signer = object::generate_signer(&constructor_ref);
        // TODO: store extend_ref?

        move_to(&object_signer, Registry {
            // TODO: functionality to update owner
            owner_address: @owner,
            router_address: @0x1, // TODO: remove fully

            feeds: simple_map::new(),
            configs: simple_map::new(),
            upkeep_feed_id_set: simple_map::new(),
        });
    }

    fun get_state_addr(): address {
        object::create_object_address(&@data_feeds, APP_OBJECT_SEED)
    }

    public entry fun set_feeds(account: &signer, feed_ids: vector<vector<u8>>, descriptions: vector<String>, config_id: vector<u8>, upkeep: address) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        // TODO: address to object, compare object owner

        assert_is_owner_or_router(registry, signer::address_of(account));

        assert_no_duplicates(&feed_ids);

        assert!(vector::length(&feed_ids) == vector::length(&descriptions), error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS));

        assert!(upkeep != @0x0, error::invalid_argument(EINVALID_UPKEEP));

        vector::zip(feed_ids, descriptions, |feed_id, description|{
            assert!(!simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_EXISTS));

            let feed = Feed {
                description,
                config_id,
                upkeep,
                upkeep_requested: false,
                benchmark: 0,
                report: vector::empty(),
                observation_timestamp: 0
            };
            simple_map::add(&mut registry.feeds, feed_id, feed);

            if (simple_map::contains_key(&registry.upkeep_feed_id_set, &upkeep)) {
                let upkeep_feed_ids = simple_map::borrow_mut(&mut registry.upkeep_feed_id_set, &upkeep);
                vector::push_back(upkeep_feed_ids, feed_id);
            } else {
                let upkeep_feed_ids = vector[feed_id];
                simple_map::add(&mut registry.upkeep_feed_id_set, upkeep, upkeep_feed_ids);
            };

            event::emit(FeedSet {
                feed_id,
                description,
                config_id,
                upkeep,
            });
        });
    }

    public entry fun remove_feeds(account: &signer, feed_ids: vector<vector<u8>>) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        assert_is_owner(registry, signer::address_of(account));

        assert_no_duplicates(&feed_ids);

        vector::for_each(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));
            let (_, feed) = simple_map::remove(&mut registry.feeds, &feed_id);

            // must exist since we always create the map entry in set_feeds.
            let upkeep_feed_ids = simple_map::borrow_mut(&mut registry.upkeep_feed_id_set, &feed.upkeep);

            vector::remove_value(upkeep_feed_ids, &feed_id);
            if (vector::is_empty(upkeep_feed_ids)) {
                simple_map::remove(&mut registry.upkeep_feed_id_set, &feed.upkeep);
            }
        });
    }

    public entry fun set_feed_configs(account: &signer, config_ids: vector<vector<u8>>, deviation_thresholds: vector<u256>, staleness_seconds: vector<u256>) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        assert_is_owner(registry, signer::address_of(account));

        let len = vector::length(&config_ids);
        assert!(len == vector::length(&deviation_thresholds), error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS));
        assert!(len == vector::length(&staleness_seconds), error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS));

        // TODO: the solidity contract does not check that no duplicates exist in config_ids,
        // but we do it here which allows us to iterate through config_ids in reverse order.
        // should we need to remove this precondition, we can consider vector::reverse'ing the
        // vectors first, similar to vector::zip.
        assert_no_duplicates(&config_ids);

        while (len > 0) {
            let config_id = vector::pop_back(&mut config_ids);
            let deviation_threshold = vector::pop_back(&mut deviation_thresholds);
            let staleness_seconds = vector::pop_back(&mut staleness_seconds);

            simple_map::upsert(&mut registry.configs, config_id, Config {
                deviation_threshold: deviation_threshold,
                staleness_seconds: staleness_seconds,
            });

            event::emit(FeedConfigSet {
                config_id,
                deviation_threshold,
                staleness_seconds,
            });

            len = len - 1;
        }
    }

    public entry fun update_descriptions(account: &signer, feed_ids: vector<vector<u8>>, descriptions: vector<String>) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        assert_is_owner(registry, signer::address_of(account));

        assert!(vector::length(&feed_ids) == vector::length(&descriptions), error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS));

        vector::zip(feed_ids, descriptions, |feed_id, description|{
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);
            feed.description = description;

            event::emit(FeedDescriptionUpdated {
                feed_id,
                description,
            });
        });
    }

    public entry fun update_feed_config_id(account: &signer, feed_ids: vector<vector<u8>>, config_id: vector<u8>) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        assert_is_owner(registry, signer::address_of(account));

        // TODO: not in the solidity contract, but we make sure that the config exists first.
        assert!(simple_map::contains_key(&registry.configs, &config_id), error::invalid_argument(ECONFIG_NOT_CONFIGURED));

        vector::for_each(feed_ids, |feed_id| {
            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);
            feed.config_id = config_id;

            event::emit(FeedConfigIdUpdated {
                feed_id,
                config_id,
            });
        });
    }

    public entry fun update_upkeep(account: &signer, feed_ids: vector<vector<u8>>, upkeep: address) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        assert_is_owner(registry, signer::address_of(account));

        assert!(upkeep != @0x0, error::invalid_argument(EINVALID_UPKEEP));

        vector::for_each(feed_ids, |feed_id| {
            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);
            let prev_upkeep = feed.upkeep;

            feed.upkeep = upkeep;

            let prev_upkeep_feed_ids = simple_map::borrow_mut(&mut registry.upkeep_feed_id_set, &prev_upkeep);
            vector::remove_value(prev_upkeep_feed_ids, &feed_id);
            if (vector::is_empty(prev_upkeep_feed_ids)) {
                simple_map::remove(&mut registry.upkeep_feed_id_set, &prev_upkeep);
            };

            if (simple_map::contains_key(&registry.upkeep_feed_id_set, &upkeep)) {
                let upkeep_feed_ids = simple_map::borrow_mut(&mut registry.upkeep_feed_id_set, &upkeep);
                vector::push_back(upkeep_feed_ids, feed_id);
            } else {
                let upkeep_feed_ids = vector[feed_id];
                simple_map::add(&mut registry.upkeep_feed_id_set, upkeep, upkeep_feed_ids);
            };

            event::emit(UpkeepUpdated {
                feed_id,
                upkeep,
            });
        });
    }

    public entry fun request_upkeep(account: &signer, feed_ids: vector<vector<u8>>) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        assert_is_owner_or_router(registry, signer::address_of(account));

        vector::for_each(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);
            feed.upkeep_requested = true;

            event::emit(UpkeepRequested {
                feed_id,
            });
        });
    }

    fun to_u32be(data: &vector<u8>, offset: u64): u32 {
        let ret: u32 = 0;
        for (i in 0..4) {
            let value = *vector::borrow(data, offset + i);
            ret = (ret << 8) | (value as u32);
        };
        ret
    }

    fun from_i192(data: &vector<u8>, offset: u64): u256 {
        let ret: u256 = 0;
        for (i in 0..24) {
            let value = *vector::borrow(data, offset + i);
            ret = (ret << 8) | (value as u256);
        };
        ret
    }

    // Keystone receiver function interface
    public entry fun on_report(account: &signer, raw_report: vector<u8>, signatures: vector<vector<u8>>) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        let authority = account;// TODO, use some other signer made for registry
        let report_context = vector::slice(&raw_report, 0, 32);
        let raw_report = vector::slice(&raw_report, 32, vector::length(&raw_report));
        let signatures = vector::map(signatures, |signature| keystone::forwarder::signature_from_bytes(signature));
        let (_metadata, data) = keystone::forwarder::validate_report(authority, raw_report, report_context, signatures);
        // TODO: slice data into N length reports
        let reports = vector[data];
        perform_upkeep(registry, reports);
    }

    fun perform_upkeep(registry: &mut Registry, reports: vector<vector<u8>>) {
        // TODO: this function requires extracting the benchmarks from the reports, fee management,
        // signature validation (if needed on this layer), and then finally updating the feeds.
        // TODO: this assumes report_data is directly provided here, which probably won't be the
        // case.
        // TODO: this requires some validation of the caller.

        vector::for_each(reports, |report_data| {
            let feed_id = vector::slice(&report_data, 0, 32);
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));
            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);

            let schema = (*vector::borrow(&feed_id, 0) as u16) << 8 | (*vector::borrow(&feed_id, 1) as u16);

            let observation_timestamp: u32;
            let benchmark_price: u256;
            if (schema == BASIC_SCHEMA) {
                observation_timestamp = to_u32be(&report_data, 8);
                benchmark_price = from_i192(&report_data, 64);
            } else if (schema == PREMIUM_SCHEMA) {
                observation_timestamp = to_u32be(&report_data, 8);
                benchmark_price = from_i192(&report_data, 64);
            } else if (schema == BLOCK_PREMIUM_SCHEMA) {
                observation_timestamp = to_u32be(&report_data, 4);
                benchmark_price = from_i192(&report_data, 8);
            } else {
                abort error::invalid_argument(EINVALID_REPORT)
            };

            feed.observation_timestamp = (observation_timestamp as u256);
            feed.benchmark = benchmark_price;
            feed.report = report_data;
            feed.upkeep_requested = false;

            event::emit(FeedUpdated {
                feed_id,
                timestamp: (observation_timestamp as u256),
                benchmark: benchmark_price,
                report: report_data,
            });
        });
    }

    public fun get_benchmarks(account: &signer, feed_ids: vector<vector<u8>>): vector<BenchmarkResult> acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        assert_authorized_data_fetch(registry, signer::address_of(account), &feed_ids);

        vector::map(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow(&registry.feeds, &feed_id);
            BenchmarkResult {
                benchmark: feed.benchmark,
                observation_timestamp: feed.observation_timestamp
            }
        })
    }

    public fun get_reports(account: &signer, feed_ids: vector<vector<u8>>): vector<ReportResult> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());

        assert_authorized_data_fetch(registry, signer::address_of(account), &feed_ids);

        vector::map(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow(&registry.feeds, &feed_id);
            ReportResult {
                report: feed.report,
                observation_timestamp: feed.observation_timestamp
            }
        })
    }

    public fun get_feed_metadata(feed_ids: vector<vector<u8>>): vector<FeedMetadataResult> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());

        vector::map(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow(&registry.feeds, &feed_id);
            let config = simple_map::borrow(&registry.configs, &feed.config_id);

            FeedMetadataResult {
                description: feed.description,
                config_id: feed.config_id,
                deviation_threshold: config.deviation_threshold,
                staleness_seconds: config.staleness_seconds,
                upkeep_requested: feed.upkeep_requested
            }
        })
    }

    public fun get_feed_configs(config_ids: vector<vector<u8>>): vector<FeedConfigResult> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());

        vector::map(config_ids, |config_id| {
            assert!(simple_map::contains_key(&registry.configs, &config_id), error::invalid_argument(ECONFIG_NOT_CONFIGURED));

            let config = simple_map::borrow(&registry.configs, &config_id);
            FeedConfigResult {
                deviation_threshold: config.deviation_threshold,
                staleness_seconds: config.staleness_seconds,
            }
        })
    }

    public fun get_upkeep_feed_ids(upkeep: address): (vector<vector<u8>>) acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());

        assert!(simple_map::contains_key(&registry.upkeep_feed_id_set, &upkeep), error::invalid_argument(EINVALID_UPKEEP));

        let upkeep_feed_ids = simple_map::borrow(&registry.upkeep_feed_id_set, &upkeep);
        *upkeep_feed_ids
    }

    public fun read_benchmark_value(result: &BenchmarkResult): u256 {
        result.benchmark
    }

    public fun read_benchmark_timestamp(result: &BenchmarkResult): u256 {
        result.observation_timestamp
    }

    public fun read_report_value(result: &ReportResult): vector<u8> {
        result.report
    }

    public fun read_report_timestamp(result: &ReportResult): u256 {
        result.observation_timestamp
    }

    public fun read_feed_metadata_description(result: &FeedMetadataResult): String {
        result.description
    }

    public fun read_feed_metadata_config_id(result: &FeedMetadataResult): vector<u8> {
        result.config_id
    }

    public fun read_feed_metadata_deviation_threshold(result: &FeedMetadataResult): u256 {
        result.deviation_threshold
    }

    public fun read_feed_metadata_staleness_seconds(result: &FeedMetadataResult): u256 {
        result.staleness_seconds
    }

    public fun read_feed_metadata_upkeep_requested(result: &FeedMetadataResult): bool {
        result.upkeep_requested
    }

    public fun read_feed_config_deviation_threshold(result: &FeedConfigResult): u256 {
        result.deviation_threshold
    }

    public fun read_feed_config_staleness_seconds(result: &FeedConfigResult): u256 {
        result.staleness_seconds
    }
}
