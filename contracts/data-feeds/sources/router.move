module data_feeds::router {
    use std::error;
    use std::signer;
    use std::string::String;
    use std::vector;

    use aptos_framework::object::{Self, ExtendRef};

    use data_feeds::registry::{Self, BenchmarkResult, ReportResult};

    const APP_OBJECT_SEED: vector<u8> = b"ROUTER";

    struct Router has key, store, drop {
        owner_address: address,
        extend_ref: ExtendRef,

        // TODO: fee manager
    }

    // TODO: add mechanism for distribution
    struct NonbillableAccessCapability has drop, store {}

    #[event]
    struct NonbillableUserAdded has drop, store {
        user: address
    }

    #[event]
    struct NonbillableUserRemoved has drop, store {
        user: address
    }

    const EUNAUTHORIZED_NONBILLABLE_ACCESS: u64 = 0;
    const ENO_SUCH_FEED: u64 = 1;
    const ENOT_OWNER: u64 = 2;

    fun assert_is_owner(router: &Router, target_address: address) {
        assert!(router.owner_address == target_address, error::invalid_argument(ENOT_OWNER));
    }

    fun init_module(account: &signer) {
        let constructor_ref = object::create_named_object(
            account,
            APP_OBJECT_SEED,
        );
        let _object_address = object::address_from_constructor_ref(&constructor_ref);

        // Store an ExtendRef alongside the object.
        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let object_signer = object::generate_signer(&constructor_ref);

        // TODO: drop owner_address and just use transfer() on object for ownership transfers?

        move_to(&object_signer, Router {
            owner_address: @owner,
            extend_ref,
        });
    }

    fun get_state_addr(): address {
        object::create_object_address(&@data_feeds, APP_OBJECT_SEED)
    }

    public fun get_benchmarks(_account: &signer, feed_ids: vector<vector<u8>>, _billing_data: vector<u8>): vector<BenchmarkResult> acquires Router {
        // TODO: handle billing

        let router = borrow_global<Router>(get_state_addr());

        get_benchmarks_internal(router, feed_ids)
    }

    public fun get_benchmarks_nonbillable(feed_ids: vector<vector<u8>>, _cap: &NonbillableAccessCapability): vector<BenchmarkResult> acquires Router {
        let router = borrow_global<Router>(get_state_addr());

        get_benchmarks_internal(router, feed_ids)
    }

    fun get_benchmarks_internal(router: &Router, feed_ids: vector<vector<u8>>): vector<BenchmarkResult> {
        let router_signer = object::generate_signer_for_extending(&router.extend_ref);

        registry::get_benchmarks(&router_signer, feed_ids)
    }

    public fun get_reports(_account: &signer, feed_ids: vector<vector<u8>>, _billing_data: vector<u8>): vector<ReportResult> acquires Router {
        // TODO: handle billing

        let router = borrow_global<Router>(get_state_addr());

        get_reports_internal(router, feed_ids)
    }

    public fun get_reports_nonbillable(feed_ids: vector<vector<u8>>, _cap: &NonbillableAccessCapability): vector<ReportResult> acquires Router {
        let router = borrow_global<Router>(get_state_addr());

        get_reports_internal(router, feed_ids)
    }

    fun get_reports_internal(router: &Router, feed_ids: vector<vector<u8>>): vector<ReportResult> {
        let router_signer = object::generate_signer_for_extending(&router.extend_ref);

        registry::get_reports(&router_signer, feed_ids)
    }

    public fun get_descriptions(feed_ids: vector<vector<u8>>): vector<String> acquires Router {
        let _router = borrow_global<Router>(get_state_addr());

        let results = registry::get_feed_metadata(feed_ids);
        vector::map(results, |metadata| registry::read_feed_metadata_description(&metadata))
    }

    public entry fun request_upkeep(_feed_ids: vector<vector<u8>>, _billing_data: vector<u8>) {
        // TODO: handle billing and implement
    }

    public entry fun configure_feeds(account: &signer, feed_ids: vector<vector<u8>>, descriptions: vector<String>, config_id: vector<u8>, upkeep: address, _fee_config_id: vector<u8>) acquires Router {
        // TODO: set new fee config
        let router = borrow_global<Router>(get_state_addr());
        assert_is_owner(router, signer::address_of(account));

        let router_signer = object::generate_signer_for_extending(&router.extend_ref);
        registry::set_feeds(&router_signer, feed_ids, descriptions, config_id, upkeep);
    }
}
