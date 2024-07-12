module data_feeds::router {
    use std::error;
    use std::event;
    use std::signer;
    use std::simple_map::{Self, SimpleMap};
    use std::string::String;
    use std::vector;

    use aptos_framework::aptos_account;
    use aptos_framework::object::{Self, ExtendRef};

    use data_feeds::registry::{Self, BenchmarkResult, ReportResult};

    struct Router has key, store, drop {
        owner_address: address,
        extend_ref: ExtendRef,

        feed_id_to_registry_address: SimpleMap<vector<u8>, address>,

        // TODO: fee manager
    }

    // TODO: add mechanism for distribution
    struct NonbillableAccessCapability has drop, store {}

    #[event]
    struct Initialized has drop, store {
        address: address,
    }

    #[event]
    struct NonbillableUserAdded has drop, store {
        user: address
    }

    #[event]
    struct NonbillableUserRemoved has drop, store {
        user: address
    }

    #[event]
    struct RegistrySet has drop, store {
        feed_id: vector<u8>,
        registry_address: address,
        previous_registry_address: address
    }

    #[event]
    struct FeeManagerSet has drop, store {
        current_fee_manager_address: address,
        previous_fee_manager_address: address,
    }

    const EUNAUTHORIZED_NONBILLABLE_ACCESS: u64 = 0;
    const ENO_SUCH_FEED: u64 = 1;
    const ENOT_OWNER: u64 = 2;

    fun assert_is_owner(router: &Router, target_address: address) {
        assert!(router.owner_address == target_address, error::invalid_argument(ENOT_OWNER));
    }

    public entry fun initialize(owner_address: address) {
        let constructor_ref = object::create_object(owner_address);
        let object_address = object::address_from_constructor_ref(&constructor_ref);

        // Create an account alongside the object.
        aptos_account::create_account(object_address);

        // Store an ExtendRef alongside the object.
        let object_signer = object::generate_signer(&constructor_ref);
        let extend_ref = object::generate_extend_ref(&constructor_ref);

        // TODO: drop owner_address and just use transfer() on object for ownership transfers

        move_to(&object_signer, Router {
            owner_address,
            extend_ref,

            feed_id_to_registry_address: simple_map::new(),
        });

        event::emit<Initialized>(
            Initialized {
                address: object_address,
            },
        );
    }

    fun get_registry_to_feed_ids(router: &Router, feed_ids: &vector<vector<u8>>): SimpleMap<address, vector<vector<u8>>> {
        let registry_to_feed_ids = simple_map::new();
        vector::for_each_ref(feed_ids, |feed_id| {
            assert!(simple_map::contains_key(&router.feed_id_to_registry_address, feed_id), error::invalid_argument(ENO_SUCH_FEED));
            let registry_address = simple_map::borrow(&router.feed_id_to_registry_address, feed_id);

            if (simple_map::contains_key(&registry_to_feed_ids, registry_address)) {
                let feed_ids = simple_map::borrow_mut(&mut registry_to_feed_ids, registry_address);
                vector::push_back(feed_ids, *feed_id);
            } else {
                let feed_ids = vector[*feed_id];
                simple_map::add(&mut registry_to_feed_ids, *registry_address, feed_ids);
            };

        });
        registry_to_feed_ids
    }

    public fun get_benchmarks(_account: &signer, router_address: address, feed_ids: vector<vector<u8>>, _billing_data: vector<u8>): vector<BenchmarkResult> acquires Router {
        // TODO: handle billing

        let router = borrow_global<Router>(router_address);

        get_benchmarks_internal(router, feed_ids)
    }

    public fun get_benchmarks_nonbillable(router_address: address, feed_ids: vector<vector<u8>>, _cap: &NonbillableAccessCapability): vector<BenchmarkResult> acquires Router {
        let router = borrow_global<Router>(router_address);

        get_benchmarks_internal(router, feed_ids)
    }

    fun get_benchmarks_internal(router: &Router, feed_ids: vector<vector<u8>>): vector<BenchmarkResult> {
        let router_signer = object::generate_signer_for_extending(&router.extend_ref);

        let registry_to_feed_ids = get_registry_to_feed_ids(router, &feed_ids);
        let (registry_addresses, per_registry_feed_ids) = simple_map::to_vec_pair(registry_to_feed_ids);

        let registry_to_results = simple_map::new();
        vector::zip(registry_addresses, per_registry_feed_ids, |registry_address, registry_feed_ids| {
            let results = registry::get_benchmarks(&router_signer, registry_address, registry_feed_ids);
            simple_map::add(&mut registry_to_results, registry_address, results);
        });

        let ret = vector[];
        vector::for_each_reverse(feed_ids, |feed_id| {
            let registry_address = simple_map::borrow(&router.feed_id_to_registry_address, &feed_id);
            let registry_results = simple_map::borrow_mut(&mut registry_to_results, registry_address);
            vector::push_back(&mut ret, vector::pop_back(registry_results));
        });

        vector::reverse(&mut ret);
        ret
    }

    public fun get_reports(_account: &signer, router_address: address, feed_ids: vector<vector<u8>>, _billing_data: vector<u8>): vector<ReportResult> acquires Router {
        // TODO: handle billing

        let router = borrow_global<Router>(router_address);

        get_reports_internal(router, feed_ids)
    }

    public fun get_reports_nonbillable(router_address: address, feed_ids: vector<vector<u8>>, _cap: &NonbillableAccessCapability): vector<ReportResult> acquires Router {
        let router = borrow_global<Router>(router_address);

        get_reports_internal(router, feed_ids)
    }

    fun get_reports_internal(router: &Router, feed_ids: vector<vector<u8>>): vector<ReportResult> {
        let router_signer = object::generate_signer_for_extending(&router.extend_ref);

        let registry_to_feed_ids = get_registry_to_feed_ids(router, &feed_ids);
        let (registry_addresses, per_registry_feed_ids) = simple_map::to_vec_pair(registry_to_feed_ids);

        let registry_to_results = simple_map::new();
        vector::zip(registry_addresses, per_registry_feed_ids, |registry_address, registry_feed_ids| {
            let results = registry::get_reports(&router_signer, registry_address, registry_feed_ids);
            simple_map::add(&mut registry_to_results, registry_address, results);
        });

        let ret = vector[];
        vector::for_each_reverse(feed_ids, |feed_id| {
            let registry_address = simple_map::borrow(&router.feed_id_to_registry_address, &feed_id);
            let registry_results = simple_map::borrow_mut(&mut registry_to_results, registry_address);
            vector::push_back(&mut ret, vector::pop_back(registry_results));
        });

        vector::reverse(&mut ret);
        ret
    }

    public fun get_descriptions(router_address: address, feed_ids: vector<vector<u8>>): vector<String> acquires Router {
        let router = borrow_global<Router>(router_address);

        let registry_to_feed_ids = get_registry_to_feed_ids(router, &feed_ids);
        let (registry_addresses, per_registry_feed_ids) = simple_map::to_vec_pair(registry_to_feed_ids);

        let registry_to_results = simple_map::new();
        vector::zip(registry_addresses, per_registry_feed_ids, |registry_address, registry_feed_ids| {
            let results = registry::get_feed_metadata(registry_address, registry_feed_ids);
            simple_map::add(&mut registry_to_results, registry_address, results);
        });

        let ret = vector[];
        vector::for_each_reverse(feed_ids, |feed_id| {
            let registry_address = simple_map::borrow(&router.feed_id_to_registry_address, &feed_id);
            let registry_results = simple_map::borrow_mut(&mut registry_to_results, registry_address);

            let feed_metadata = vector::pop_back(registry_results);
            vector::push_back(&mut ret, registry::read_feed_metadata_description(&feed_metadata));
        });

        vector::reverse(&mut ret);
        ret
    }

    public entry fun request_upkeep(_router_address: address, _feed_ids: vector<vector<u8>>, _billing_data: vector<u8>) {
        // TODO: handle billing and implement
    }

    public entry fun configure_feeds(account: &signer, router_address: address, feed_ids: vector<vector<u8>>, descriptions: vector<String>, config_id: vector<u8>, upkeep: address, registry_address: address, _fee_config_id: vector<u8>) acquires Router {
        // TODO: set new fee config
        let router = borrow_global<Router>(router_address);
        assert_is_owner(router, signer::address_of(account));

        let router_signer = object::generate_signer_for_extending(&router.extend_ref);
        registry::set_feeds(&router_signer, registry_address, feed_ids, descriptions, config_id, upkeep);

        set_registry(account, router_address, feed_ids, registry_address);
    }

    public entry fun set_registry(account: &signer, router_address: address, feed_ids: vector<vector<u8>>, registry_address: address) acquires Router {
        let router = borrow_global_mut<Router>(router_address);
        assert_is_owner(router, signer::address_of(account));

        vector::for_each(feed_ids, |feed_id| {
            let previous_registry_address = @0x0;
            if (simple_map::contains_key(&router.feed_id_to_registry_address, &feed_id)) {
                previous_registry_address = *simple_map::borrow(&router.feed_id_to_registry_address, &feed_id);
                simple_map::upsert(&mut router.feed_id_to_registry_address, feed_id, registry_address);
            } else {
                simple_map::add(&mut router.feed_id_to_registry_address, feed_id, registry_address);
            };

            event::emit(RegistrySet {
                feed_id,
                registry_address,
                previous_registry_address,
            });
        });
    }
}
