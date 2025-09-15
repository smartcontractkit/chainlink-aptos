module data_feeds::registry {
    use std::error;
    use std::event;
    use std::option;
    use std::signer;
    use std::simple_map::{Self, SimpleMap};
    use std::string::{Self, String};
    use std::vector;

    use aptos_framework::object::{Self, ExtendRef, TransferRef, Object};

    friend data_feeds::router;

    const APP_OBJECT_SEED: vector<u8> = b"REGISTRY";

    struct Registry has key, store, drop {
        extend_ref: ExtendRef,
        transfer_ref: TransferRef,
        owner_address: address,
        pending_owner_address: address,
        feeds: SimpleMap<vector<u8>, Feed>,
        allowed_workflow_owners: vector<vector<u8>>,
        allowed_workflow_names: vector<vector<u8>>
    }

    struct RegistryMigrationStatus has key, store, drop {
        callback_registered: bool
    }

    // The report field is now unused, and will be an empty
    // vector<u8> in all future writes
    struct Feed has key, store, drop, copy {
        description: String,
        config_id: vector<u8>,
        benchmark: u256,
        report: vector<u8>,
        observation_timestamp: u256
    }

    struct Benchmark has store, drop, copy {
        benchmark: u256,
        observation_timestamp: u256
    }

    struct Report has store, drop {
        report: vector<u8>,
        observation_timestamp: u256
    }

    struct FeedMetadata has store, drop, key {
        description: String,
        config_id: vector<u8>
    }

    struct WorkflowConfig {
        allowed_workflow_owners: vector<vector<u8>>,
        allowed_workflow_names: vector<vector<u8>>
    }

    struct FeedConfig {
        feed_id: vector<u8>,
        feed: Feed
    }

    #[event]
    struct FeedDescriptionUpdated has drop, store {
        feed_id: vector<u8>,
        description: String
    }

    #[event]
    struct FeedRemoved has drop, store {
        feed_id: vector<u8>
    }

    #[event]
    struct FeedSet has drop, store {
        feed_id: vector<u8>,
        description: String,
        config_id: vector<u8>
    }

    #[event]
    struct FeedUnset has drop, store {
        feed_id: vector<u8>
    }

    // The report field is now unused, and will be an empty
    // vector<u8> in all future writes
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
        report_timestamp: u256
    }

    #[event]
    struct WriteSkippedFeedNotSet has drop, store {
        feed_id: vector<u8>
    }

    #[event]
    struct OwnershipTransferRequested has drop, store {
        from: address,
        to: address
    }

    #[event]
    struct OwnershipTransferred has drop, store {
        from: address,
        to: address
    }

    // Errors
    const ENOT_OWNER: u64 = 1;
    const EDUPLICATE_ELEMENTS: u64 = 2;
    const EFEED_EXISTS: u64 = 3;
    const EFEED_NOT_CONFIGURED: u64 = 4;
    const ECONFIG_NOT_CONFIGURED: u64 = 5;
    const EUNEQUAL_ARRAY_LENGTHS: u64 = 6;
    const EINVALID_REPORT: u64 = 7;
    const EUNAUTHORIZED_WORKFLOW_NAME: u64 = 8;
    const EUNAUTHORIZED_WORKFLOW_OWNER: u64 = 9;
    const ECANNOT_TRANSFER_TO_SELF: u64 = 10;
    const ENOT_PROPOSED_OWNER: u64 = 11;
    const EEMPTY_WORKFLOW_OWNERS: u64 = 12;
    const EINVALID_RAW_REPORT: u64 = 13;
    const EALREADY_MIGRATED: u64 = 14;

    // Schema types (For Backwards Compatibility) only
    const SCHEMA_V3: u16 = 3;
    const SCHEMA_V4: u16 = 4;

    inline fun assert_is_owner(
        registry: &Registry, target_address: address
    ) {
        assert!(
            registry.owner_address == target_address,
            error::permission_denied(ENOT_OWNER)
        );
    }

    fun assert_no_duplicates<T>(a: &vector<T>) {
        let len = vector::length(a);
        for (i in 0..len) {
            for (j in (i + 1)..len) {
                assert!(
                    vector::borrow(a, i) != vector::borrow(a, j),
                    error::invalid_argument(EDUPLICATE_ELEMENTS)
                );
            }
        }
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @data_feeds, ENOT_OWNER);

        let constructor_ref = object::create_named_object(publisher, APP_OBJECT_SEED);

        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let object_signer = object::generate_signer(&constructor_ref);

        // callback for on_report function
        let cb =
            aptos_framework::function_info::new_function_info(
                publisher,
                string::utf8(b"registry"),
                string::utf8(b"on_report")
            );
        // register to receive platform::forwarder reports
        platform::storage::register(publisher, cb, new_proof());

        // callback for on_report_secondary function
        let cb_secondary =
            aptos_framework::function_info::new_function_info(
                publisher,
                string::utf8(b"registry"),
                string::utf8(b"on_report_secondary")
            );
        // register to receive platform_secondary::forwarder reports
        platform_secondary::storage::register(
            publisher, cb_secondary, new_proof_secondary()
        );

        move_to(
            &object_signer,
            Registry {
                owner_address: @owner,
                pending_owner_address: @0x0,
                extend_ref,
                transfer_ref,
                feeds: simple_map::new(),
                allowed_workflow_names: vector[],
                allowed_workflow_owners: vector[]
            }
        );

        move_to(
            &object_signer,
            RegistryMigrationStatus { callback_registered: true }
        );
    }

    inline fun get_state_addr(): address {
        object::create_object_address(&@data_feeds, APP_OBJECT_SEED)
    }

    // This function can be called into to register callbacks in future Forwarders
    public entry fun register_callbacks(publisher: &signer) acquires Registry {
        assert!(signer::address_of(publisher) == @data_feeds, ENOT_OWNER);

        assert!(
            !exists<RegistryMigrationStatus>(get_state_addr()),
            EALREADY_MIGRATED
        );

        let registry = borrow_global_mut<Registry>(get_state_addr());
        let object_signer = object::generate_signer_for_extending(&registry.extend_ref);

        // callback for on_report_secondary function
        let cb_secondary =
            aptos_framework::function_info::new_function_info(
                publisher,
                string::utf8(b"registry"),
                string::utf8(b"on_report_secondary")
            );
        // register to receive platform_secondary::forwarder reports
        platform_secondary::storage::register(
            publisher, cb_secondary, new_proof_secondary()
        );

        move_to(
            &object_signer,
            RegistryMigrationStatus { callback_registered: true }
        );
    }

    public entry fun set_feeds(
        authority: &signer,
        feed_ids: vector<vector<u8>>,
        descriptions: vector<String>,
        config_id: vector<u8>
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        assert_is_owner(registry, signer::address_of(authority));
        set_feeds_internal(registry, feed_ids, descriptions, config_id);
    }

    public(friend) fun set_feeds_unchecked(
        feed_ids: vector<vector<u8>>,
        descriptions: vector<String>,
        config_id: vector<u8>
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
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
            error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS)
        );

        vector::zip_ref(
            &feed_ids,
            &descriptions,
            |feed_id, description| {
                assert!(
                    !simple_map::contains_key(&registry.feeds, feed_id),
                    error::invalid_argument(EFEED_EXISTS)
                );

                let feed = Feed {
                    description: *description,
                    config_id,
                    benchmark: 0,
                    report: vector::empty(),
                    observation_timestamp: 0
                };
                simple_map::add(&mut registry.feeds, *feed_id, feed);

                event::emit(
                    FeedSet { feed_id: *feed_id, description: *description, config_id }
                );
            }
        );
    }

    public entry fun remove_feeds(
        authority: &signer, feed_ids: vector<vector<u8>>
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        assert_is_owner(registry, signer::address_of(authority));

        assert_no_duplicates(&feed_ids);

        vector::for_each(
            feed_ids,
            |feed_id| {
                assert!(
                    simple_map::contains_key(&registry.feeds, &feed_id),
                    error::invalid_argument(EFEED_NOT_CONFIGURED)
                );
                simple_map::remove(&mut registry.feeds, &feed_id);

                event::emit(FeedUnset { feed_id: feed_id });
            }
        );
    }

    public entry fun update_descriptions(
        authority: &signer, feed_ids: vector<vector<u8>>, descriptions: vector<String>
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        assert_is_owner(registry, signer::address_of(authority));

        assert!(
            vector::length(&feed_ids) == vector::length(&descriptions),
            error::invalid_argument(EUNEQUAL_ARRAY_LENGTHS)
        );

        vector::zip_ref(
            &feed_ids,
            &descriptions,
            |feed_id, description| {
                assert!(
                    simple_map::contains_key(&registry.feeds, feed_id),
                    error::invalid_argument(EFEED_NOT_CONFIGURED)
                );

                let feed = simple_map::borrow_mut(&mut registry.feeds, feed_id);
                feed.description = *description;

                event::emit(
                    FeedDescriptionUpdated { feed_id: *feed_id, description: *description }
                );
            }
        );
    }

    inline fun to_u32be(data: vector<u8>): u32 {
        // reverse big endian to little endian
        vector::reverse(&mut data);
        aptos_std::from_bcs::to_u32(data)
    }

    inline fun to_u256be(data: vector<u8>): u256 {
        // reverse big endian to little endian
        vector::reverse(&mut data);
        aptos_std::from_bcs::to_u256(data)
    }

    /// Serves as a proof type for the dispatch engine, used to authenticate and handle incoming message callbacks.
    /// This identifier links callback registration with the `on_report` event and enables secure retrieval of callback data.
    /// Only has the `drop` ability to prevent copying and persisting in global storage.
    struct OnReceive has drop {}

    struct OnReceiveSecondary has drop {}

    /// Creates a new OnReceive object.
    inline fun new_proof(): OnReceive {
        OnReceive {}
    }

    /// Creates a new OnReceive object.
    inline fun new_proof_secondary(): OnReceiveSecondary {
        OnReceiveSecondary {}
    }

    // Callback function to be called via a @platform::forwarder contract
    // This callback will be accessed via a 'primary' @platform instance
    public fun on_report<T: key>(_meta: object::Object<T>): option::Option<u128> acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        // Fetch report data from the @platform::storage contract
        // Saved previously by the platform::forwarder contract
        let (metadata, data) = platform::storage::retrieve(new_proof());

        let parsed_metadata = platform::storage::parse_report_metadata(metadata);

        let workflow_owner =
            platform::storage::get_report_metadata_workflow_owner(&parsed_metadata);
        assert!(
            vector::contains(&registry.allowed_workflow_owners, &workflow_owner),
            EUNAUTHORIZED_WORKFLOW_OWNER
        );

        let workflow_name =
            platform::storage::get_report_metadata_workflow_name(&parsed_metadata);
        assert!(
            vector::is_empty(&registry.allowed_workflow_names)
                || vector::contains(&registry.allowed_workflow_names, &workflow_name),
            EUNAUTHORIZED_WORKFLOW_NAME
        );

        let (feed_ids, reports) = parse_raw_report(&data);
        vector::zip_ref(
            &feed_ids,
            &reports,
            |feed_id, report| {
                perform_update(registry, *feed_id, *report);
            }
        );

        option::none()
    }

    // Callback function to be called via a @platform::forwarder contract
    // This callback will be accessed via a different 'secondary' @platform instance
    public fun on_report_secondary<T: key>(
        _meta: object::Object<T>
    ): option::Option<u128> acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());

        // Fetch report data from the @platform::storage contract
        // Saved previously by the platform::forwarder contract
        let (metadata, data) =
            platform_secondary::storage::retrieve(new_proof_secondary());

        let parsed_metadata =
            platform_secondary::storage::parse_report_metadata(metadata);

        let workflow_owner =
            platform_secondary::storage::get_report_metadata_workflow_owner(
                &parsed_metadata
            );
        assert!(
            vector::contains(&registry.allowed_workflow_owners, &workflow_owner),
            EUNAUTHORIZED_WORKFLOW_OWNER
        );

        let workflow_name =
            platform_secondary::storage::get_report_metadata_workflow_name(
                &parsed_metadata
            );
        assert!(
            vector::is_empty(&registry.allowed_workflow_names)
                || vector::contains(&registry.allowed_workflow_names, &workflow_name),
            EUNAUTHORIZED_WORKFLOW_NAME
        );

        let (feed_ids, reports) = parse_raw_report(&data);
        vector::zip_ref(
            &feed_ids,
            &reports,
            |feed_id, report| {
                perform_update(registry, *feed_id, *report);
            }
        );

        option::none()
    }

    public entry fun set_workflow_config(
        authority: &signer,
        allowed_workflow_owners: vector<vector<u8>>,
        allowed_workflow_names: vector<vector<u8>>
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        assert_is_owner(registry, signer::address_of(authority));
        assert!(
            !vector::is_empty(&allowed_workflow_owners),
            error::invalid_argument(EEMPTY_WORKFLOW_OWNERS)
        );
        assert_no_duplicates(&allowed_workflow_owners);
        assert_no_duplicates(&allowed_workflow_names);

        registry.allowed_workflow_owners = allowed_workflow_owners;
        registry.allowed_workflow_names = allowed_workflow_names;
    }

    #[view]
    public fun get_migration_status(): bool {
        exists<RegistryMigrationStatus>(get_state_addr())
    }

    #[view]
    public fun get_workflow_config(): WorkflowConfig acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());

        WorkflowConfig {
            allowed_workflow_owners: registry.allowed_workflow_owners,
            allowed_workflow_names: registry.allowed_workflow_names
        }
    }

    // N.B. This FeedConfig type has a report field. These report fields are now being
    // set to an empty vector<u8> on the on_report path(s).
    #[view]
    public fun get_feeds(): vector<FeedConfig> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());
        let feed_configs = vector[];
        let (feed_ids, feeds) = simple_map::to_vec_pair(registry.feeds);
        vector::zip_ref(
            &feed_ids,
            &feeds,
            |feed_id, feed| {
                vector::push_back(
                    &mut feed_configs,
                    FeedConfig { feed_id: *feed_id, feed: *feed }
                );
            }
        );
        feed_configs
    }

    // Parse ETH ABI encoded raw data into multiple reports
    fun parse_raw_report(data: &vector<u8>): (vector<vector<u8>>, vector<vector<u8>>) {
        let data_len: u64 = vector::length(data);
        let offset: u64 = 0;

        assert!(
            data_len > 64,
            error::invalid_argument(EINVALID_RAW_REPORT)
        );

        assert!(
            to_u256be(vector::slice(data, offset, offset + 32)) == 32,
            32
        );
        offset = offset + 32;

        let count = (to_u256be(vector::slice(data, offset, offset + 32)) as u64);
        offset = offset + 32;

        let is_v03: bool = data_len == count * 13 * 32 + 2 * 32;
        let is_benchmark: bool = data_len == count * 3 * 32 + 64;

        let feed_ids;
        let reports;

        if (is_v03) {
            // skip offsets table
            offset = offset + 32 * count;
            (feed_ids, reports) = parse_v03_reports(data, offset, count);
        } else if (is_benchmark) {
            (feed_ids, reports) = parse_benchmark_reports(data, offset, count);
        } else {
            abort error::invalid_argument(EINVALID_RAW_REPORT);
        };

        (feed_ids, reports)
    }

    // Parse Benchmark + Timestamp reports
    fun parse_benchmark_reports(
        data: &vector<u8>, offset: u64, count: u64
    ): (vector<vector<u8>>, vector<vector<u8>>) {
        let feed_ids: vector<vector<u8>> = vector::empty<vector<u8>>();
        let reports: vector<vector<u8>> = vector::empty<vector<u8>>();

        let len = 2 * 32;
        for (i in 0..count) {
            let feed_id = vector::slice(data, offset, offset + 32);
            vector::push_back(&mut feed_ids, feed_id);
            offset = offset + 32;
            let report = vector::slice(data, offset, offset + len);
            vector::push_back(&mut reports, report);
            offset = offset + len;
        };

        (feed_ids, reports)
    }

    // Parse Mercury V03 reports
    fun parse_v03_reports(
        data: &vector<u8>, offset: u64, count: u64
    ): (vector<vector<u8>>, vector<vector<u8>>) {
        let feed_ids: vector<vector<u8>> = vector::empty<vector<u8>>();
        let reports: vector<vector<u8>> = vector::empty<vector<u8>>();

        for (i in 0..count) {
            let feed_id = vector::slice(data, offset, offset + 32);
            vector::push_back(&mut feed_ids, feed_id);
            offset = offset + 32;

            assert!(
                to_u256be(vector::slice(data, offset, offset + 32)) == 64,
                64
            );
            offset = offset + 32;

            let len = (to_u256be(vector::slice(data, offset, offset + 32)) as u64);
            offset = offset + 32;

            let report = vector::slice(data, offset, offset + len);
            vector::push_back(&mut reports, report);
            offset = offset + len;
        };

        (feed_ids, reports)
    }

    // Extract the Benchmark and Timestamp from a report, and update the feeds values
    fun perform_update(
        registry: &mut Registry, feed_id: vector<u8>, report_data: vector<u8>
    ) {
        if (!simple_map::contains_key(&registry.feeds, &feed_id)) {
            event::emit(WriteSkippedFeedNotSet { feed_id });

            return
        };

        let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);

        let is_v03 = vector::length(&report_data) == 9 * 32; // 288 bytes

        let observation_timestamp_ptr: u64 = if (is_v03) { 3 * 32 }
        else { 32 };
        let benchmark_price_ptr: u64 = if (is_v03) { 6 * 32 }
        else { 32 };

        let observation_timestamp: u256 =
            (
                to_u32be(
                    vector::slice(
                        &report_data,
                        observation_timestamp_ptr - 4,
                        observation_timestamp_ptr
                    )
                ) as u256
            );

        // NOTE: aptos has no signed integer types, so can't parse as i192, this is a raw representation
        let benchmark_price: u256 =
            to_u256be(
                vector::slice(&report_data, benchmark_price_ptr, benchmark_price_ptr
                    + 32)
            );

        if (feed.observation_timestamp >= observation_timestamp) {
            event::emit(
                StaleReport {
                    feed_id,
                    latest_timestamp: feed.observation_timestamp,
                    report_timestamp: observation_timestamp
                }
            );
            return;
        };

        feed.observation_timestamp = observation_timestamp;
        feed.benchmark = benchmark_price;

        if (vector::length(&feed.report) != 0) {
            // Set to empty as value, as reports are deprecated.
            feed.report = vector::empty<u8>();
        };

        event::emit(
            FeedUpdated {
                feed_id,
                timestamp: observation_timestamp,
                benchmark: benchmark_price,
                report: vector::empty<u8>()
            }
        );
    }

    // Getters

    public fun get_benchmarks(
        authority: &signer, feed_ids: vector<vector<u8>>
    ): vector<Benchmark> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());
        assert_is_owner(registry, signer::address_of(authority));
        get_benchmarks_internal(registry, feed_ids)
    }

    public(friend) fun get_benchmarks_unchecked(
        feed_ids: vector<vector<u8>>
    ): vector<Benchmark> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());
        get_benchmarks_internal(registry, feed_ids)
    }

    fun get_benchmarks_internal(
        registry: &Registry, feed_ids: vector<vector<u8>>
    ): vector<Benchmark> {
        vector::map(
            feed_ids,
            |feed_id| {
                assert!(
                    simple_map::contains_key(&registry.feeds, &feed_id),
                    error::invalid_argument(EFEED_NOT_CONFIGURED)
                );
                let feed = simple_map::borrow(&registry.feeds, &feed_id);
                Benchmark {
                    benchmark: feed.benchmark,
                    observation_timestamp: feed.observation_timestamp
                }
            }
        )
    }

    public fun get_reports(
        authority: &signer, feed_ids: vector<vector<u8>>
    ): vector<Report> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());
        assert_is_owner(registry, signer::address_of(authority));
        get_reports_internal(registry, feed_ids)
    }

    public(friend) fun get_reports_unchecked(
        feed_ids: vector<vector<u8>>
    ): vector<Report> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());
        get_reports_internal(registry, feed_ids)
    }

    fun get_reports_internal(
        registry: &Registry, feed_ids: vector<vector<u8>>
    ): vector<Report> {
        vector::map(
            feed_ids,
            |feed_id| {
                assert!(
                    simple_map::contains_key(&registry.feeds, &feed_id),
                    error::invalid_argument(EFEED_NOT_CONFIGURED)
                );

                let feed = simple_map::borrow(&registry.feeds, &feed_id);
                Report {
                    report: feed.report,
                    observation_timestamp: feed.observation_timestamp
                }
            }
        )
    }

    #[view]
    public fun get_feed_metadata(
        feed_ids: vector<vector<u8>>
    ): vector<FeedMetadata> acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());

        vector::map(
            feed_ids,
            |feed_id| {
                assert!(
                    simple_map::contains_key(&registry.feeds, &feed_id),
                    error::invalid_argument(EFEED_NOT_CONFIGURED)
                );

                let feed = simple_map::borrow(&registry.feeds, &feed_id);

                FeedMetadata { description: feed.description, config_id: feed.config_id }
            }
        )
    }

    // Ownership functions

    #[view]
    public fun get_owner(): address acquires Registry {
        let registry = borrow_global<Registry>(get_state_addr());
        registry.owner_address
    }

    public entry fun transfer_ownership(authority: &signer, to: address) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        assert_is_owner(registry, signer::address_of(authority));
        assert!(
            registry.owner_address != to,
            error::invalid_argument(ECANNOT_TRANSFER_TO_SELF)
        );

        registry.pending_owner_address = to;

        event::emit(OwnershipTransferRequested { from: registry.owner_address, to });
    }

    public entry fun accept_ownership(authority: &signer) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        assert!(
            registry.pending_owner_address == signer::address_of(authority),
            error::permission_denied(ENOT_PROPOSED_OWNER)
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

    #[test_only]
    fun set_up_test(
        publisher: &signer, platform: &signer, platform_secondary: &signer
    ) {
        use aptos_framework::account::{Self};
        account::create_account_for_test(signer::address_of(publisher));

        platform::forwarder::init_module_for_testing(platform);
        platform::storage::init_module_for_testing(platform);

        platform_secondary::forwarder::init_module_for_testing(platform_secondary);
        platform_secondary::storage::init_module_for_testing(platform_secondary);

        init_module(publisher);
    }

    #[test_only]
    fun set_feed_for_test(
        feed_id: vector<u8>, description: String, config_id: vector<u8>
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        set_feeds_internal(
            registry,
            vector[feed_id],
            vector[description],
            config_id
        );
    }

    #[test_only]
    fun perform_update_for_test(
        feed_id: vector<u8>,
        observation_timestamp: u256,
        benchmark_price: u256,
        report_data: vector<u8>
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(get_state_addr());
        assert!(
            simple_map::contains_key(&registry.feeds, &feed_id),
            error::invalid_argument(EFEED_NOT_CONFIGURED)
        );
        let feed = simple_map::borrow_mut(&mut registry.feeds, &feed_id);

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

    #[test]
    #[expected_failure(abort_code = 65549, location = Self)]
    fun test_parse_raw_report_length_failure() {
        let data =
            x"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000005";

        parse_raw_report(&data);
    }

    #[test]
    fun test_parse_raw_report() {
        // request_context = 00018463f564e082c55b7237add2a03bd6b3c35789d38be0f6964d9aba82f1a8000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000
        // metadata = 1019256d85b84c7ba85cd9b7bb94fe15b73d7ec99e3cc0f470ee5dd2a1eaac88c000000000000000000000000bc3a8582cc08d3df797ab13a6c567eadb2517b3f0f931b7145b218016bf9dde43030303045544842544300000000000000000000000000000000000000aa00010
        // 0000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c
        // raw report =
        // 0000000000000000000000000000000000000000000000000000000000000020 32
        // 0000000000000000000000000000000000000000000000000000000000000005 len=5
        // 0001111111111111111100000000000000000000000000000000000000000000 feed_id 1
        // 0000000000000000000000000000000000000000000000000000000066c2e36c obervation_timestamp 1
        // 00000000000000000000000000000000000000000000000000000000000494a8 answer 1
        // 0002111111111111111100000000000000000000000000000000000000000000 feed_id 2
        // 0000000000000000000000000000000000000000000000000000000066c2e36c obervation_timestamp 2
        // 00000000000000000000000000000000000000000000000000000000000594a8 answer 2
        // 0003111111111111111100000000000000000000000000000000000000000000 feed_id 3
        // 0000000000000000000000000000000000000000000000000000000066c2e36c obervation_timestamp 3
        // 00000000000000000000000000000000000000000000000000000000000694a8 answer 3
        // 0004111111111111111100000000000000000000000000000000000000000000 feed_id 4
        // 0000000000000000000000000000000000000000000000000000000066c2e36c obervation_timestamp 4
        // 00000000000000000000000000000000000000000000000000000000000794a8 answer 4
        // 0005111111111111111100000000000000000000000000000000000000000000 feed_id 5
        // 0000000000000000000000000000000000000000000000000000000066c2e36c obervation_timestamp 5
        // 00000000000000000000000000000000000000000000000000000000000894a8 answer 5

        let data =
            x"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000500011111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a800021111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000594a800031111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000694a800041111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000794a800051111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000894a8";

        let (feed_ids, reports) = parse_raw_report(&data);
        std::debug::print(&feed_ids);
        std::debug::print(&reports);

        assert!(
            feed_ids
                == vector[
                    x"0001111111111111111100000000000000000000000000000000000000000000",
                    x"0002111111111111111100000000000000000000000000000000000000000000",
                    x"0003111111111111111100000000000000000000000000000000000000000000",
                    x"0004111111111111111100000000000000000000000000000000000000000000",
                    x"0005111111111111111100000000000000000000000000000000000000000000"
                ],
            1
        );

        let expected_reports = vector[
            x"0000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a8",
            x"0000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000594a8",
            x"0000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000694a8",
            x"0000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000794a8",
            x"0000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000894a8"
        ];
        assert!(reports == expected_reports, 1);
    }

    #[
        test(
            owner = @owner,
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary
        )
    ]
    fun test_perform_update(
        owner: &signer,
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        let report_data =
            x"0000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a8";
        let feed_id = vector::slice(&report_data, 0, 32);
        let expected_timestamp = 0x000066c2e36c;
        let expected_benchmark = 0x0000000494a8;

        let config_id = vector[1];

        set_feeds(
            owner,
            vector[feed_id],
            vector[string::utf8(b"description")],
            config_id
        );

        let registry = borrow_global_mut<Registry>(get_state_addr());
        perform_update(registry, feed_id, report_data);

        let benchmarks = get_benchmarks(owner, vector[feed_id]);
        assert!(vector::length(&benchmarks) == 1, 1);

        let benchmark = vector::borrow(&benchmarks, 0);
        assert!(benchmark.benchmark == expected_benchmark, 1);
        assert!(benchmark.observation_timestamp == expected_timestamp, 1);
    }

    #[
        test(
            owner = @owner,
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary
        )
    ]
    #[expected_failure(abort_code = 65540, location = data_feeds::registry)]
    fun test_perform_update_not_set(
        owner: &signer,
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        let report_data =
            x"0000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a8";

        // Feed ID not stored in this report format
        let feed_id = x"0003111111111111111100000000000000000000000000000000000000000000";
        let expected_timestamp = 0x000066c2e36c;
        let expected_benchmark = 0x0000000494a8;

        let config_id = vector[1];

        let report_data_not_set =
            x"0003acdb4fce42f65d6032b18aee53efdf526cc734ad296cb57565979d883bdd0000000000000000000000000000000000000000000000000000000066ed173e0000000000000000000000000000000000000000000000000000000066ed174200000000000000007fffffffffffffffffffffffffffffffffffffffffffffff00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000066ee68c2000000000000000000000000000000000000000000000d808cc35e6ed670bd00000000000000000000000000000000000000000000000d808590c35425347980000000000000000000000000000000000000000000000d8093f5f989878e7c00";
        let feed_id_not_set =
            x"0003222222222222222200000000000000000000000000000000000000000000";

        // Only set one of the feed configs
        set_feeds(
            owner,
            vector[feed_id],
            vector[string::utf8(b"description")],
            config_id
        );

        let registry = borrow_global_mut<Registry>(get_state_addr());

        // Test this doesn't block the next update
        perform_update(registry, feed_id_not_set, report_data_not_set);

        perform_update(registry, feed_id, report_data);

        let benchmarks = get_benchmarks(owner, vector[feed_id]);
        assert!(vector::length(&benchmarks) == 1, 1);

        let benchmark = vector::borrow(&benchmarks, 0);

        assert!(benchmark.benchmark == expected_benchmark, 1);
        assert!(benchmark.observation_timestamp == expected_timestamp, 1);

        registry = borrow_global_mut<Registry>(get_state_addr());

        // Test this doesn't undo the previous update
        perform_update(registry, feed_id_not_set, report_data_not_set);

        benchmarks = get_benchmarks(owner, vector[feed_id]);
        assert!(vector::length(&benchmarks) == 1, 1);

        benchmark = vector::borrow(&benchmarks, 0);

        assert!(benchmark.benchmark == expected_benchmark, 1);
        assert!(benchmark.observation_timestamp == expected_timestamp, 1);

        // Fail on attempting to fetch benchmark for feed_id_not_set
        get_benchmarks(owner, vector[feed_id_not_set]);
    }

    #[test]
    fun test_parse_raw_report_v3() {
        // request_context = 00018463f564e082c55b7237add2a03bd6b3c35789d38be0f6964d9aba82f1a8000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000
        // metadata = 1019256d85b84c7ba85cd9b7bb94fe15b73d7ec99e3cc0f470ee5dd2a1eaac88c000000000000000000000000bc3a8582cc08d3df797ab13a6c567eadb2517b3f0f931b7145b218016bf9dde43030303045544842544300000000000000000000000000000000000000aa00010
        // 0000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c
        // raw report =
        // 0000000000000000000000000000000000000000000000000000000000000020 32
        // 0000000000000000000000000000000000000000000000000000000000000002 len=2
        // 0000000000000000000000000000000000000000000000000000000000000040 offset
        // 00000000000000000000000000000000000000000000000000000000000001c0 offset
        // 0003111111111111111100000000000000000000000000000000000000000000 feed_id
        // 0000000000000000000000000000000000000000000000000000000000000040 offset
        // 0000000000000000000000000000000000000000000000000000000000000120 len=228
        // 0003111111111111111100000000000000000000000000000000000000000000
        // 0000000000000000000000000000000000000000000000000000000066b3a12c
        // 0000000000000000000000000000000000000000000000000000000066b3a12c
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 0000000000000000000000000000000000000000000000000000000066c2e36c
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 0003222222222222222200000000000000000000000000000000000000000000 feed_id
        // 0000000000000000000000000000000000000000000000000000000000000040 offset
        // 0000000000000000000000000000000000000000000000000000000000000120 len=228
        // 0003222222222222222200000000000000000000000000000000000000000000
        // 0000000000000000000000000000000000000000000000000000000066b3a12c
        // 0000000000000000000000000000000000000000000000000000000066b3a12c
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 0000000000000000000000000000000000000000000000000000000066c2e36c
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 00000000000000000000000000000000000000000000000000000000000494a8
        // 00000000000000000000000000000000000000000000000000000000000494a8

        let data =
            x"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c000031111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000031111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066b3a12c0000000000000000000000000000000000000000000000000000000066b3a12c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a80000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a800032222222222222222000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000032222222222222222000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066b3a12c0000000000000000000000000000000000000000000000000000000066b3a12c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a80000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a8";

        let (feed_ids, reports) = parse_raw_report(&data);

        assert!(
            feed_ids
                == vector[
                    x"0003111111111111111100000000000000000000000000000000000000000000",
                    x"0003222222222222222200000000000000000000000000000000000000000000"
                ],
            1
        );

        let expected_reports = vector[
            x"00031111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066b3a12c0000000000000000000000000000000000000000000000000000000066b3a12c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a80000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a8",
            x"00032222222222222222000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066b3a12c0000000000000000000000000000000000000000000000000000000066b3a12c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a80000000000000000000000000000000000000000000000000000000066c2e36c00000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a800000000000000000000000000000000000000000000000000000000000494a8"
        ];
        assert!(reports == expected_reports, 1);
    }

    #[
        test(
            owner = @owner,
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary
        )
    ]
    fun test_perform_update_v3(
        owner: &signer,
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        let report_data =
            x"0003fbba4fce42f65d6032b18aee53efdf526cc734ad296cb57565979d883bdd0000000000000000000000000000000000000000000000000000000066ed173e0000000000000000000000000000000000000000000000000000000066ed174200000000000000007fffffffffffffffffffffffffffffffffffffffffffffff00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000066ee68c2000000000000000000000000000000000000000000000d808cc35e6ed670bd00000000000000000000000000000000000000000000000d808590c35425347980000000000000000000000000000000000000000000000d8093f5f989878e7c00";
        let feed_id = vector::slice(&report_data, 0, 32);
        let expected_timestamp = 0x000066ed1742;
        let expected_benchmark = 0x000d808cc35e6ed670bd00;

        let config_id = vector[1];

        set_feeds(
            owner,
            vector[feed_id],
            vector[string::utf8(b"description")],
            config_id
        );

        let registry = borrow_global_mut<Registry>(get_state_addr());
        perform_update(registry, feed_id, report_data);

        let benchmarks = get_benchmarks(owner, vector[feed_id]);
        assert!(vector::length(&benchmarks) == 1, 1);

        let benchmark = vector::borrow(&benchmarks, 0);

        assert!(benchmark.benchmark == expected_benchmark, 1);
        assert!(benchmark.observation_timestamp == expected_timestamp, 1);
    }

    #[
        test(
            owner = @owner,
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary
        )
    ]
    #[expected_failure(abort_code = 65540, location = data_feeds::registry)]
    fun test_perform_update_v3_feed_not_set(
        owner: &signer,
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        let report_data =
            x"0003fbba4fce42f65d6032b18aee53efdf526cc734ad296cb57565979d883bdd0000000000000000000000000000000000000000000000000000000066ed173e0000000000000000000000000000000000000000000000000000000066ed174200000000000000007fffffffffffffffffffffffffffffffffffffffffffffff00000000000000007fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000066ee68c2000000000000000000000000000000000000000000000d808cc35e6ed670bd00000000000000000000000000000000000000000000000d808590c35425347980000000000000000000000000000000000000000000000d8093f5f989878e7c00";
        let feed_id = vector::slice(&report_data, 0, 32);
        let expected_timestamp = 0x000066ed1742;
        let expected_benchmark = 0x000d808cc35e6ed670bd00;

        let config_id = vector[1];

        let report_data_not_set =
            x"0003acdb4fce42f65d6032b18aee53efdf526cc734ad296cb57565979d883bdd0000000000000000000000000000000000000000000000000000000076ed173e0000000000000000000000000000000000000000000000000000000076ed174200000000000000004affffffffffffffffffffffffffffffffffffffffffffff00000000000000004affffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000076ee68c2000000000000000000000000000000000000000000000e808cc35e6ed670bd00000000000000000000000000000000000000000000000e808590c35425347980000000000000000000000000000000000000000000000e8093f5f989878e7c00";
        let feed_id_not_set = vector::slice(&report_data_not_set, 0, 32);

        // Only set one of the feed configs
        set_feeds(
            owner,
            vector[feed_id],
            vector[string::utf8(b"description")],
            config_id
        );

        let registry = borrow_global_mut<Registry>(get_state_addr());

        // Test this doesn't block the next update
        perform_update(registry, feed_id_not_set, report_data_not_set);

        perform_update(registry, feed_id, report_data);

        let benchmarks = get_benchmarks(owner, vector[feed_id]);
        assert!(vector::length(&benchmarks) == 1, 1);

        let benchmark = vector::borrow(&benchmarks, 0);

        assert!(benchmark.benchmark == expected_benchmark, 1);
        assert!(benchmark.observation_timestamp == expected_timestamp, 1);

        registry = borrow_global_mut<Registry>(get_state_addr());

        // Test this doesn't undo the previous update
        perform_update(registry, feed_id_not_set, report_data_not_set);

        benchmarks = get_benchmarks(owner, vector[feed_id]);
        assert!(vector::length(&benchmarks) == 1, 1);

        benchmark = vector::borrow(&benchmarks, 0);

        assert!(benchmark.benchmark == expected_benchmark, 1);
        assert!(benchmark.observation_timestamp == expected_timestamp, 1);

        // Fail on attempting to fetch benchmark for feed_id_not_set
        get_benchmarks(owner, vector[feed_id_not_set]);
    }

    #[
        test(
            owner = @owner,
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary,
            new_owner = @0xbeef
        )
    ]
    fun test_transfer_ownership_success(
        owner: &signer,
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer,
        new_owner: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(owner, signer::address_of(new_owner));
        accept_ownership(new_owner);

        assert!(get_owner() == signer::address_of(new_owner), 2);
    }

    #[
        test(
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary,
            unknown_user = @0xbeef
        )
    ]
    #[expected_failure(abort_code = 327681, location = data_feeds::registry)]
    fun test_transfer_ownership_failure_not_owner(
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer,
        unknown_user: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(unknown_user, signer::address_of(unknown_user));
    }

    #[
        test(
            owner = @owner,
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary
        )
    ]
    #[expected_failure(abort_code = 65546, location = data_feeds::registry)]
    fun test_transfer_ownership_failure_transfer_to_self(
        owner: &signer,
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(owner, signer::address_of(owner));
    }

    #[
        test(
            owner = @owner,
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary,
            new_owner = @0xbeef
        )
    ]
    #[expected_failure(abort_code = 327691, location = data_feeds::registry)]
    fun test_transfer_ownership_failure_not_proposed_owner(
        owner: &signer,
        publisher: &signer,
        platform: &signer,
        platform_secondary: &signer,
        new_owner: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(owner, @0xfeeb);
        accept_ownership(new_owner);
    }

    #[
        test(
            publisher = @data_feeds,
            platform = @platform,
            platform_secondary = @platform_secondary
        )
    ]
    fun test_retrieve_benchmark(
        publisher: &signer, platform: &signer, platform_secondary: &signer
    ) acquires Registry {
        set_up_test(publisher, platform, platform_secondary);

        let feed_id = vector[1, 2, 3, 4, 5];
        set_feed_for_test(
            feed_id,
            string::utf8(b"test feed"),
            vector[6, 7, 8]
        );

        let observation_timestamp = 123u256;
        let benchmark_price = 456u256;
        let report_data = vector[9, 0, 1];
        perform_update_for_test(
            feed_id,
            observation_timestamp,
            benchmark_price,
            report_data
        );

        let benchmarks = get_benchmarks_unchecked(vector[feed_id]);
        assert!(vector::length(&benchmarks) == 1, 1);
        let benchmark = vector::borrow(&benchmarks, 0);
        assert!(get_benchmark_value(benchmark) == benchmark_price, 2);
        assert!(get_benchmark_timestamp(benchmark) == observation_timestamp, 3);

        let reports = get_reports_unchecked(vector[feed_id]);
        assert!(vector::length(&reports) == 1, 1);
        let report = vector::borrow(&reports, 0);
        assert!(get_report_value(report) == report_data, 4);
        assert!(get_report_timestamp(report) == observation_timestamp, 5);
    }
}
