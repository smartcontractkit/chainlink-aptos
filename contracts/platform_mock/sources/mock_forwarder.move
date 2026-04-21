module platform_mock::mock_forwarder {
    use std::vector;
    use std::signer;
    use aptos_framework::event;

    #[event]
    struct ReportProcessed has drop, store {
        receiver: address,
        raw_report_len: u64,
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
        event::emit(ReportProcessed {
            receiver,
            raw_report_len: vector::length(&raw_report),
        });
    }

    #[test_only]
    use std::vector as test_vector;

    #[test(owner = @platform_mock, transmitter = @0xCAFE)]
    fun test_report_is_permissionless(owner: &signer, transmitter: &signer) {
        initialize(owner);
        let raw = test_vector::empty<u8>();
        test_vector::push_back(&mut raw, 1);
        let sigs = test_vector::empty<vector<u8>>();
        report(transmitter, @0xBEEF, raw, sigs);
    }

    #[test(owner = @platform_mock, transmitter = @0xCAFE)]
    fun test_report_ignores_garbage_sigs(owner: &signer, transmitter: &signer) {
        initialize(owner);
        let raw = test_vector::empty<u8>();
        let sigs = test_vector::empty<vector<u8>>();
        let junk = test_vector::empty<u8>();
        test_vector::push_back(&mut junk, 0xFF);
        test_vector::push_back(&mut sigs, junk);
        report(transmitter, @0xDEAD, raw, sigs);
    }

    #[test(owner = @platform_mock, transmitter = @0xCAFE)]
    fun test_report_large_payload(owner: &signer, transmitter: &signer) {
        initialize(owner);
        let raw = test_vector::empty<u8>();
        let i = 0;
        while (i < 1024) {
            test_vector::push_back(&mut raw, ((i % 256) as u8));
            i = i + 1;
        };
        let sigs = test_vector::empty<vector<u8>>();
        report(transmitter, @0xFEED, raw, sigs);
    }
}
