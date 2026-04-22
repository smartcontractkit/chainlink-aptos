/// DEV / TEST ONLY. Permissionless mock of `platform::forwarder` for cre-cli
/// `simulate`. Skips sig/config validation; dispatch path mirrors prod.
module platform_mock::mock_forwarder {
    use std::signer;
    use std::vector;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::event;
    use aptos_framework::fungible_asset;
    use aptos_framework::object;

    use platform_mock::mock_storage;

    const E_NOT_INITIALIZED: u64 = 1;
    const E_INVALID_REPORT_VERSION: u64 = 2;
    const E_CALLBACK_DATA_NOT_CONSUMED: u64 = 3;
    const E_RECEIVER_NOT_REGISTERED: u64 = 4;

    #[event]
    struct ReportProcessed has drop, store {
        receiver: address,
        workflow_execution_id: vector<u8>,
        report_id: vector<u8>,
    }

    struct State has key {
        owner: address,
    }

    public entry fun initialize(owner: &signer) {
        move_to(owner, State { owner: signer::address_of(owner) });
    }

    public entry fun report(
        _transmitter: &signer,
        receiver: address,
        raw_report: vector<u8>,
        _signatures: vector<vector<u8>>,
    ) {
        assert!(exists<State>(@platform_mock), E_NOT_INITIALIZED);
        assert!(mock_storage::is_registered(receiver), E_RECEIVER_NOT_REGISTERED);

        // raw_report = report_context(96) || report;
        // report = version(1) || workflow_execution_id(32) || ... || metadata@[45..109) || data@[109..).
        let report = vector::slice(&raw_report, 96, vector::length(&raw_report));
        let report_version = *vector::borrow(&report, 0);
        assert!(report_version == 1, E_INVALID_REPORT_VERSION);

        let workflow_execution_id = vector::slice(&report, 1, 33);
        let metadata = vector::slice(&report, 45, 109);
        let data = vector::slice(&report, 109, vector::length(&report));
        let report_id = vector::slice(&report, 107, 109);

        dispatch(receiver, metadata, data);

        event::emit(ReportProcessed { receiver, workflow_execution_id, report_id });
    }

    fun dispatch(receiver: address, metadata: vector<u8>, data: vector<u8>) {
        let meta = mock_storage::insert(receiver, metadata, data);
        dispatchable_fungible_asset::derived_supply(meta);
        let obj_address = object::object_address<fungible_asset::Metadata>(&meta);
        assert!(!mock_storage::storage_exists(obj_address), E_CALLBACK_DATA_NOT_CONSUMED);
    }

    #[test_only]
    use platform_mock::mock_test_receiver;

    #[test_only]
    fun make_well_formed_report(): vector<u8> {
        let ctx = vector::empty<u8>();
        let i = 0;
        while (i < 96) { vector::push_back(&mut ctx, 0); i = i + 1; };

        let body = vector::empty<u8>();
        vector::push_back(&mut body, 1);
        let i = 0;
        while (i < 108) { vector::push_back(&mut body, ((i % 256) as u8)); i = i + 1; };
        vector::push_back(&mut body, 0xDE);
        vector::push_back(&mut body, 0xAD);
        vector::push_back(&mut body, 0xBE);
        vector::push_back(&mut body, 0xEF);

        vector::append(&mut ctx, body);
        ctx
    }

    #[test(owner = @platform_mock, publisher = @platform_mock, transmitter = @0xCAFE)]
    fun test_report_dispatches_through_storage(
        owner: &signer, publisher: &signer, transmitter: &signer,
    ) {
        mock_storage::init_module_for_testing(publisher);
        initialize(owner);
        mock_test_receiver::register(publisher);

        let raw = make_well_formed_report();
        let sigs = vector::empty<vector<u8>>();
        report(transmitter, signer::address_of(publisher), raw, sigs);
    }

    #[test(owner = @platform_mock, publisher = @platform_mock, transmitter = @0xCAFE)]
    #[expected_failure(abort_code = E_RECEIVER_NOT_REGISTERED, location = Self)]
    fun test_report_unregistered_receiver_aborts_in_forwarder(
        owner: &signer, publisher: &signer, transmitter: &signer,
    ) {
        mock_storage::init_module_for_testing(publisher);
        initialize(owner);
        let raw = make_well_formed_report();
        let sigs = vector::empty<vector<u8>>();
        report(transmitter, @0xBEEF, raw, sigs);
    }

    #[test(owner = @platform_mock, publisher = @platform_mock, transmitter = @0xCAFE)]
    #[expected_failure(abort_code = E_INVALID_REPORT_VERSION, location = Self)]
    fun test_report_bad_version_aborts(
        owner: &signer, publisher: &signer, transmitter: &signer,
    ) {
        mock_storage::init_module_for_testing(publisher);
        initialize(owner);
        mock_test_receiver::register(publisher);
        let raw = vector::empty<u8>();
        let i = 0;
        while (i < 96) { vector::push_back(&mut raw, 0); i = i + 1; };
        vector::push_back(&mut raw, 9);
        let i = 0;
        while (i < 120) { vector::push_back(&mut raw, 0); i = i + 1; };
        let sigs = vector::empty<vector<u8>>();
        report(transmitter, signer::address_of(publisher), raw, sigs);
    }

    #[test(transmitter = @0xCAFE)]
    #[expected_failure(abort_code = E_NOT_INITIALIZED, location = Self)]
    fun test_report_uninitialized_forwarder_aborts(transmitter: &signer) {
        let raw = make_well_formed_report();
        let sigs = vector::empty<vector<u8>>();
        report(transmitter, @0xBEEF, raw, sigs);
    }
}
