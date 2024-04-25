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
        timestamp: address,
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

    const ENOT_OWNER: u64 = 1;
    const EDUPLICATE_ELEMENTS: u64 = 2;
    const EFEED_EXISTS: u64 = 3;
    const EFEED_NOT_CONFIGURED: u64 = 4;
    const EINVALID_UPKEEP: u64 = 5;
    const EUNAUTHORIZED_DATA_FETCH: u64 = 6;
    const EUNAUTHORIZED_ROUTER_OPERATION: u64 = 7;
    const EUNEQUAL_ARRAY_LENGTHS: u64 = 8;

    fun assert_is_owner(registry: &DataFeedsRegistry, target_address: address) {
        assert!(registry.owner_address == target_address, error::invalid_argument(ENOT_OWNER));
    }

    fun assert_no_duplicates<T>(a: &vector<T>) {
        let len = vector::length(a);
        for (i in 0..len) {
            for (j in (i + 1)..len) {
                assert!(vector::borrow(a, i) != vector::borrow(a, j), error::invalid_argument(EDUPLICATE_ELEMENTS));
            }
        }
    }

    public entry fun initialize(resource_account: &signer, owner_address: address) {
        move_to(resource_account, DataFeedsRegistry {
            owner_address: owner_address,

            feeds: simple_map::new(),
            configs: simple_map::new(),
            upkeep_feed_id_set: simple_map::new(),
        });
    }

    public entry fun set_feeds(account: &signer, registry_address: address, feed_ids: vector<vector<u8>>, descriptions: vector<String>, config_id: vector<u8>, upkeep: address) acquires DataFeedsRegistry {
        let registry = borrow_global_mut<DataFeedsRegistry>(registry_address);

        // TODO: this is a permissioned to the router address in solidity contracts
        assert_is_owner(registry, signer::address_of(account));

        assert_no_duplicates(&feed_ids);

        assert!(vector::length(&feed_ids) == vector::length(&descriptions), error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS));

        assert!(upkeep != @0x0, error::invalid_argument(EINVALID_UPKEEP));

        vector::zip(feed_ids, descriptions, |feed_id, description|{
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

        // TODO: the solidity contract does not check that no duplicates exist in config_ids, so we
        // reverse first to match the behavior of allowing setting the same config more than once,
        // and that the latest provided config is the one that ultimately gets set.

        vector::reverse(&mut config_ids);
        vector::reverse(&mut deviation_thresholds);
        vector::reverse(&mut staleness_seconds);

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
}
