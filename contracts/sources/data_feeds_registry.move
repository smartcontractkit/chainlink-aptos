module chainlink::data_feeds_registry {
    use std::account::{Self};
    use std::error;
    use std::event;
    use std::signer;
    use std::simple_map::{Self, SimpleMap};
    use std::string::{Self, String, utf8};
    use std::vector::{Self};

    // TODO: figure out link_address, router, verifier_proxy
    struct DataFeedsRegistry has key, store, drop {
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
        staleness_seconds: u256,
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

    fun assert_is_owner(registry: &DataFeedsRegistry, target_address: address) {
        assert!(registry.owner_address == target_address, error::invalid_argument(ENOT_OWNER));
    }

    fun assert_is_owner_or_router(registry: &DataFeedsRegistry, target_address: address) {
        assert!(registry.owner_address == target_address || registry.router_address == target_address, error::invalid_argument(EUNAUTHORIZED_ROUTER_OPERATION));
    }

    fun assert_authorized_data_fetch(registry: &DataFeedsRegistry, target_address: address, feed_ids: &vector<vector<u8>>) {
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

    public entry fun initialize(resource_account: &signer, owner_address: address, router_address: address) {
        move_to(resource_account, DataFeedsRegistry {
            // TODO: functionality to update owner and router addresses
            owner_address: owner_address,
            router_address: router_address,

            feeds: simple_map::new(),
            configs: simple_map::new(),
            upkeep_feed_id_set: simple_map::new(),
        });
    }

    public entry fun set_feeds(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>, descriptions: vector<String>, config_id: vector<u8>, upkeep: address) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        assert_is_owner_or_router(registry, signer::address_of(account));

        assert_no_duplicates(&feed_ids);

        assert!(vector::length(&feed_ids) == vector::length(&descriptions), error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS));

        assert!(upkeep != @0x0, error::invalid_argument(EINVALID_UPKEEP));

        vector::zip(feed_ids, descriptions, |feed_id, description|{
            assert!(!simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_EXISTS));

            let feed = Feed {
                description: description,
                config_id: config_id,
                upkeep: upkeep,
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
                feed_id: feed_id,
                description: description,
                config_id: config_id,
                upkeep: upkeep,
            });
        });
    }

    public entry fun remove_feeds(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

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

    public entry fun set_feed_configs(account: &signer, registry_address: address, config_ids: vector<vector<u8>>, deviation_thresholds: vector<u256>, staleness_seconds: vector<u256>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

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
                config_id: config_id,
                deviation_threshold: deviation_threshold,
                staleness_seconds: staleness_seconds,
            });

            len = len - 1;
        }
    }

    public entry fun update_descriptions(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>, descriptions: vector<String>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        assert_is_owner(registry, signer::address_of(account));

        assert!(vector::length(&feed_ids) == vector::length(&descriptions), error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS));

        vector::zip(feed_ids, descriptions, |feed_id, description|{
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);
            feed.description = description;

            event::emit(FeedDescriptionUpdated {
                feed_id: feed_id,
                description: description,
            });
        });
    }

    public entry fun update_feed_config_id(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>, config_id: vector<u8>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        assert_is_owner(registry, signer::address_of(account));

        // TODO: not in the solidity contract, but we make sure that the config exists first.
        assert!(simple_map::contains_key(&registry.configs, &config_id), error::invalid_argument(ECONFIG_NOT_CONFIGURED));

        vector::for_each(feed_ids, |feed_id| {
            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);
            feed.config_id = config_id;

            event::emit(FeedConfigIdUpdated {
                feed_id: feed_id,
                config_id: config_id,
            });
        });
    }

    public entry fun update_upkeep(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>, upkeep: address) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

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
                feed_id: feed_id,
                upkeep: upkeep,
            });
        });
    }

    public entry fun request_upkeep(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        assert_is_owner_or_router(registry, signer::address_of(account));

        vector::for_each(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);
            feed.upkeep_requested = true;

            event::emit(UpkeepRequested {
                feed_id: feed_id,
            });
        });
    }

    fun from_u32(data: &vector<u8>, offset: u64): u32 {
        let ret: u32 = 0;
        for (i in 0..4) {
            let value = *vector::borrow(data, offset + i);
            ret = (ret << 8) | (value as u32);
        };
        return ret
    }

    fun from_i192(data: &vector<u8>, offset: u64): u256 {
        let ret: u256 = 0;
        for (i in 0..24) {
            let value = *vector::borrow(data, offset + i);
            ret = (ret << 8) | (value as u256);
        };
        return ret
    }

    public entry fun perform_upkeep(account: &signer, registry_address: address, report_datas: vector<vector<u8>>) acquires DataFeedsRegistry {
        // TODO: this function requires extracting the benchmarks from the reports, fee management,
        // signature validation (if needed on this layer), and then finally updating the feeds.
        // TODO: this assumes report_data is directly provided here, which probably won't be the
        // case.

        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        vector::for_each(report_datas, |report_data| {
            let feed_id = vector::slice(&report_data, 0, 32);
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));
            let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);

            let schema = (*vector::borrow(&feed_id, 0) as u16) << 8 | (*vector::borrow(&feed_id, 1) as u16);

            let observation_timestamp: u32;
            let benchmark_price: u256;
            if (schema == BASIC_SCHEMA) {
                observation_timestamp = from_u32(&report_data, 8);
                benchmark_price = from_i192(&report_data, 64);
            } else if (schema == PREMIUM_SCHEMA) {
                observation_timestamp = from_u32(&report_data, 8);
                benchmark_price = from_i192(&report_data, 64);
            } else if (schema == BLOCK_PREMIUM_SCHEMA) {
                observation_timestamp = from_u32(&report_data, 4);
                benchmark_price = from_i192(&report_data, 8);
            } else {
                abort error::invalid_argument(EINVALID_REPORT)
            };

            feed.observation_timestamp = (observation_timestamp as u256);
            feed.benchmark = benchmark_price;
            feed.report = report_data;
            feed.upkeep_requested = false;

            event::emit(FeedUpdated {
                feed_id: feed_id,
                timestamp: (observation_timestamp as u256),
                benchmark: benchmark_price,
                report: report_data,
            });
        });
    }

    public fun get_benchmarks(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>): (vector<u256>, vector<u256>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        assert_authorized_data_fetch(registry, signer::address_of(account), &feed_ids);

        let benchmarks = vector[];
        let observation_timestamps = vector[];

        vector::for_each(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow(&registry.feeds, &feed_id);
            vector::push_back(&mut benchmarks, feed.benchmark);
            vector::push_back(&mut observation_timestamps, feed.observation_timestamp);
        });

        return (benchmarks, observation_timestamps)
    }

    public fun get_reports(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>): (vector<vector<u8>>, vector<u256>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        assert_authorized_data_fetch(registry, signer::address_of(account), &feed_ids);

        let reports = vector[];
        let observation_timestamps = vector[];

        vector::for_each(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow(&registry.feeds, &feed_id);
            vector::push_back(&mut reports, feed.report);
            vector::push_back(&mut observation_timestamps, feed.observation_timestamp);
        });

        return (reports, observation_timestamps)
    }

    public fun get_feed_metadata(registry_address: address, feed_ids: vector<vector<u8>>): (vector<String>, vector<vector<u8>>, vector<u256>, vector<u256>, vector<bool>) acquires DataFeedsRegistry {
        let descriptions = vector[];
        let config_ids = vector[];
        let deviation_thresholds = vector[];
        let staleness_seconds = vector[];
        let upkeeps_requested = vector[];

        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        vector::for_each(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&registry.feeds, &feed_id), error::invalid_argument(EFEED_NOT_CONFIGURED));

            let feed = simple_map::borrow(&registry.feeds, &feed_id);
            vector::push_back(&mut descriptions, feed.description);
            vector::push_back(&mut config_ids, feed.config_id);
            vector::push_back(&mut upkeeps_requested, feed.upkeep_requested);

            let config = simple_map::borrow(&registry.configs, &feed.config_id);
            vector::push_back(&mut deviation_thresholds, config.deviation_threshold);
            vector::push_back(&mut staleness_seconds, config.staleness_seconds);
        });

        return (descriptions, config_ids, deviation_thresholds, staleness_seconds, upkeeps_requested)
    }

    public fun get_feed_configs(registry_address: address, config_ids: vector<vector<u8>>): (vector<u256>, vector<u256>) acquires DataFeedsRegistry {
        let deviation_thresholds = vector[];
        let staleness_seconds = vector[];

        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        vector::for_each(config_ids, |config_id| {
            assert!(simple_map::contains_key(&registry.configs, &config_id), error::invalid_argument(ECONFIG_NOT_CONFIGURED));

            let config = simple_map::borrow(&registry.configs, &config_id);
            vector::push_back(&mut deviation_thresholds, config.deviation_threshold);
            vector::push_back(&mut staleness_seconds, config.staleness_seconds);
        });

        return (deviation_thresholds, staleness_seconds)
    }

    public fun get_upkeep_feed_ids(registry_address: address, upkeep: address): (vector<vector<u8>>) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        assert!(simple_map::contains_key(&registry.upkeep_feed_id_set, &upkeep), error::invalid_argument(EINVALID_UPKEEP));

        let upkeep_feed_ids = simple_map::borrow(&registry.upkeep_feed_id_set, &upkeep);
        return *upkeep_feed_ids
    }
}
