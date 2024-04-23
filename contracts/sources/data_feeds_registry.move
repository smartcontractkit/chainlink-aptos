module chainlink::data_feeds_registry {
    use std::account::{Self};
    use std::error;
    use std::simple_map::{Self, SimpleMap};
    use std::string::{Self, String, utf8};

    struct DataFeedsRegistry has key, store, drop {
        signer_cap: account::SignerCapability,

        link_address: address,
        router: address,
        // TODO: separate verifier proxy for verify_bulk()?
        verifier_proxy: address,

        feeds: SimpleMap<vector<u8>, Feed>,
        configs: SimpleMap<vector<u8>, Config>,
        // upkeep to feed ids
        upkeep_feed_id_set: SimpleMap<address, vector<vector<u8>>>
    }

    struct Feed has key, store, drop {
        description: String,
        configId: vector<u8>,
        upkeep: address,
        upkeep_requested: bool,
        // TODO: int256 in solidity contract
        benchmark: u128,
        report: vector<u8>,
        // TODO: uint256 in solidity contract
        observation_timestamp: u128,
    }

    struct Config has key, store, drop {
        // TODO: uint256 in solidity contract
        deviation_threshold: u128,
        // TODO: uint256 in solidity contract
        staleness_seconds: u128,
    }

    #[event]
    struct FeedConfigIdUpdated has drop, store {
        feed_id: vector<u8>,
        config_id: vector<u8>,
    }

    #[event]
    struct FeedConfigSet has drop, store {
        config_id: vector<u8>,
        // TODO: uint256 in solidity contract
        deviation_threshold: u128,
        // TODO: uint256 in solidity contract
        staleness_seconds: u128,
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
        // TODO: int256 in solidity contract
        benchmark: u128,
        report: vector<u8>
    }

    #[event]
    struct StaleReport has drop, store {
        feed_id: vector<u8>,
        // TODO: uint256 in solidity contract
        latest_timestamp: u128,
        // TODO: uint256 in solidity contract
        report_timestamp: u128,
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

    struct OwnerCapability has key, store {}

    const ENOT_OWNER: u64 = 1;
    const EDUPLICATE_FEED_IDS: u64 = 2;
    const EFEED_EXISTS: u64 = 3;
    const EFEED_NOT_CONFIGURED: u64 = 4;
    const EINVALID_UPKEEP: u64 = 5;
    const EUNAUTHORIZED_DATA_FETCH: u64 = 6;
    const EUNAUTHORIZED_ROUTER_OPERATION: u64 = 7;
    const EUNEQUAL_ARRAY_LENGTHS: u64 = 8;

    fun assert_is_owner(addr: address) {
        assert!(exists<OwnerCapability>(addr), error::invalid_argument(ENOT_OWNER))
    }

    public fun initialize(account: &signer, link_address: address, router: address, verifier_proxy: address): (OwnerCapability) {
        // this raises if the resource account already exists.
        let (resource_account, signer_cap) = account::create_resource_account(account, b"DataFeedsRegistry");
        move_to(&resource_account, DataFeedsRegistry {
            signer_cap: signer_cap,
            link_address: link_address,
            router: router,
            verifier_proxy: verifier_proxy,
            feeds: simple_map::new(),
            configs: simple_map::new(),
            upkeep_feed_id_set: simple_map::new(),
        });

        // TODO: move OwnerCapability into `account` instead?
        OwnerCapability{}
    }
}
