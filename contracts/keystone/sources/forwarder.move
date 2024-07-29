module keystone::forwarder {
    use aptos_framework::object::{Self, ExtendRef};
    use aptos_std::smart_table::{SmartTable,Self};

    use std::error;
    use std::event;
    use std::vector;
    use std::bit_vector;
    use std::option::{Self, Option};
    use std::signer;
    use std::bcs;

    const E_INVALID_DATA_LENGTH: u64 = 1;
    const E_INVALID_SIGNER: u64 = 2;
    const E_DUPLICATE_SIGNER: u64 = 3;
    const E_INVALID_SIGNATURE_COUNT: u64 = 4;
    const E_INVALID_SIGNATURE: u64 = 5;
    const E_ALREADY_PROCESSED: u64 = 6;
    const E_UNAUTHORIZED: u64 = 7;
    const E_MALFORMED_SIGNATURE: u64 = 8;
    const E_FAULT_TOLERANCE_MUST_BE_POSITIVE: u64 = 9;
    const E_EXCESS_SIGNERS: u64 = 10;
    const E_INSUFFICIENT_SIGNERS: u64 = 11;

    const MAX_ORACLES: u64 = 31;

    const APP_OBJECT_SEED: vector<u8> = b"FORWARDER";

    struct ConfigId has key, store, drop, copy {
        don_id: u32,
        config_version: u32,
    }

    struct State has key {
        owner: address,

        extend_ref: ExtendRef,

        // (don_id, config_version) => config
        configs: SmartTable<ConfigId, Config>,

        reports: SmartTable<vector<u8>, address>
    }

    struct Config has key, store, drop {
        f: u8,
        // oracles: SimpleMap<address, Oracle>,
        oracles: vector<ed25519::UnvalidatedPublicKey>,
    }

    #[event]
    struct ConfigSet has drop, store {
        don_id: u32,
        config_version: u32,
        f: u8,
        signers: vector<vector<u8>>,
    }

    #[event]
    struct ReportProcessed has drop, store {
        receiver: address,
        workflow_execution_id: vector<u8>,
        report_id: u16,
    }

    fun init_module(publisher: &signer) {
        let constructor_ref = object::create_named_object(
            publisher,
            APP_OBJECT_SEED,
        );

        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let app_signer = &object::generate_signer(&constructor_ref);

        move_to(app_signer, State {
            owner: @owner, // TODO: how to handle this, can we just use address of account passed in
            configs: smart_table::new(),
            reports: smart_table::new(),
            extend_ref,
        });
    }

    inline fun get_state_addr(): address {
        object::create_object_address(&@keystone, APP_OBJECT_SEED)
    }

    public entry fun set_config(authority: &signer, don_id: u32, config_version: u32, f: u8, oracles: vector<vector<u8>>) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());

        assert!(state.owner == signer::address_of(authority), E_UNAUTHORIZED);

        assert!(f != 0, error::invalid_argument(E_FAULT_TOLERANCE_MUST_BE_POSITIVE));
        assert!(vector::length(&oracles) <= MAX_ORACLES, error::invalid_argument(E_EXCESS_SIGNERS));
        assert!(vector::length(&oracles) >= 3 * (f as u64) + 1, error::invalid_argument(E_INSUFFICIENT_SIGNERS));

        smart_table::upsert(&mut state.configs, ConfigId {don_id, config_version}, Config {
            f,
            oracles: vector::map(oracles, |oracle| {
                ed25519::new_unvalidated_public_key_from_bytes(oracle)
            })
        });

        event::emit(ConfigSet {
            don_id,
            config_version,
            f,
            signers: oracles,
        });
    }

    public entry fun clear_config(authority: &signer, don_id: u32, config_version: u32) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());

        assert!(state.owner == signer::address_of(authority), E_UNAUTHORIZED);

        smart_table::remove(&mut state.configs, ConfigId {don_id, config_version});

        event::emit(ConfigSet {
            don_id,
            config_version,
            f: 0,
            signers: vector::empty(),
        });
    }

    use aptos_std::aptos_hash::blake2b_256;
    use aptos_std::ed25519;

    struct Signature has drop {
        public_key: ed25519::UnvalidatedPublicKey, // TODO: pass signer index rather than key to save on space and gas?
        sig: ed25519::Signature,
    }

    public fun signature_from_bytes(bytes: vector<u8>): Signature {
        assert!(vector::length(&bytes) == 96, error::invalid_argument(E_MALFORMED_SIGNATURE));
        let public_key = ed25519::new_unvalidated_public_key_from_bytes(vector::slice(&bytes, 0, 32));
        let sig = ed25519::new_signature_from_bytes(vector::slice(&bytes, 32, 96));
        Signature { sig, public_key }
    }

    inline fun transmission_id(receiver: address, workflow_execution_id: vector<u8>, report_id: u16): vector<u8> {
        let id = bcs::to_bytes(&receiver);
        vector::append(&mut id, workflow_execution_id);
        vector::append(&mut id, bcs::to_bytes(&report_id));
        id
    }

    /// The dispatch call knows both storage and indirectly the callback, thus the separate module.
    fun dispatch(address: address, data: vector<u8>) {
        let metadata = keystone::storage::insert(address, data);
        aptos_framework::dispatchable_fungible_asset::derived_supply(metadata);
    }

    public entry fun report(transmitter: &signer, receiver: address, raw_report: vector<u8>, signatures: vector<vector<u8>>) acquires State {
        let report_context = vector::slice(&raw_report, 0, 96);
        let raw_report = vector::slice(&raw_report, 96, vector::length(&raw_report));
        let signatures = vector::map(signatures, |signature| signature_from_bytes(signature));

        let (_metadata, data) = validate_report(transmitter, receiver, raw_report, report_context, signatures);
        dispatch(receiver, data); // TODO: pass metadata through
        // TODO: unable to catch failure here
    }

    fun to_u16be(data: vector<u8>): u16 {
        // reverse big endian to little endian
        vector::reverse(&mut data);
        aptos_std::from_bcs::to_u16(data)
    }

    fun to_u32be(data: vector<u8>): u32 {
        // reverse big endian to little endian
        vector::reverse(&mut data);
        aptos_std::from_bcs::to_u32(data)
    }

    fun validate_report(transmitter: &signer, receiver: address, report: vector<u8>, report_context: vector<u8>, signatures: vector<Signature>): (vector<u8>, vector<u8>) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());

        // parse out report metadata
        // version | workflow_execution_id | timestamp | don_id | config_version | ...
        let workflow_execution_id = vector::slice(&report, 1, 33);
        // _timestamp
        let don_id = vector::slice(&report, 37, 41);
        let don_id = to_u32be(don_id);
        let config_version = vector::slice(&report, 41, 45);
        let config_version = to_u32be(config_version);
        let report_id = vector::slice(&report, 107, 109);
        let report_id = to_u16be(report_id);
        let metadata = vector::slice(&report, 45, 109);
        let data = vector::slice(&report, 109, vector::length(&report));

        // NOTE: this will revert for us if don_id doesn't exist
        let config = smart_table::borrow(&state.configs, ConfigId { don_id, config_version });

        // check if report was already delivered
        let transmission_id = transmission_id(receiver, workflow_execution_id, report_id);
        let processed = smart_table::contains(&state.reports, transmission_id);
        assert!(!processed, E_ALREADY_PROCESSED);

        let required_signatures = (config.f as u64) + 1;
        assert!(vector::length(&signatures) == required_signatures, error::invalid_argument(E_INVALID_SIGNATURE_COUNT));

        // TODO: transmit already needs to split this apart, might as well pass through as one vec<>
        // blake2b(report_context, report)
        let msg = report_context;
        vector::append(&mut msg, report);
        let msg = blake2b_256(msg);

        let signed = bit_vector::new(vector::length(&config.oracles));

        vector::for_each_ref(&signatures, |signature| {
            let signature: &Signature = signature; // some compiler versions can't infer the type here

            let (valid, index) = vector::index_of(&config.oracles, &signature.public_key);
            assert!(valid, error::invalid_argument(E_INVALID_SIGNER));

            // check for duplicate signers
            let duplicate = bit_vector::is_index_set(&signed, index);
            assert!(!duplicate, error::invalid_argument(E_DUPLICATE_SIGNER));
            bit_vector::set(&mut signed, index);

            let result = ed25519::signature_verify_strict(&signature.sig, &signature.public_key, msg);
            assert!(result, error::invalid_argument(E_INVALID_SIGNATURE));

        });

        // mark as delivered
        smart_table::add(&mut state.reports, transmission_id, signer::address_of(transmitter));

        event::emit(ReportProcessed {
            receiver,
            workflow_execution_id,
            report_id,
        });

        (metadata, data)
    }

    #[view]
    public fun get_transmission_state(receiver: address, workflow_execution_id: vector<u8>, report_id: u16): bool acquires State {
        let state = borrow_global<State>(get_state_addr());
        let transmission_id = transmission_id(receiver, workflow_execution_id, report_id);

        return smart_table::contains(&state.reports, transmission_id)
    }

    #[view]
    public fun get_transmitter(receiver: address, workflow_execution_id: vector<u8>, report_id: u16): Option<address> acquires State {
        let state = borrow_global<State>(get_state_addr());
        let transmission_id = transmission_id(receiver, workflow_execution_id, report_id);

        if (!smart_table::contains(&state.reports, transmission_id)) {
            return option::none()
        };
        option::some(*smart_table::borrow(&state.reports, transmission_id))
    }

    #[test_only]
    public entry fun set_up_test(owner: &signer, account: &signer) {
        use aptos_framework::account::{Self};
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(account));

        init_module(account);
    }

    #[test_only]
    struct OracleSet has drop {
        don_id: u32,
        config_version: u32,
        f: u8,
        oracles: vector<vector<u8>>,
        signers: vector<ed25519::SecretKey>,
    }

    #[test_only]
    fun generate_oracle_set(): OracleSet {
        let don_id = 0;
        let f = 1;

        let signers = vector[];
        let oracles = vector[];
        for (i in 0..31) {
            let (sk, pk) = ed25519::generate_keys();
            vector::push_back(&mut signers, sk);
            vector::push_back(&mut oracles, ed25519::validated_public_key_to_bytes(&pk));
        };
        OracleSet {
            don_id,
            config_version: 1,
            f,
            oracles,
            signers,
        }
    }

    #[test_only]
    fun sign_report(config: &OracleSet, report: vector<u8>, report_context: vector<u8>): vector<Signature> {
        // blake2b(report_context, report)
        let msg = report_context;
        vector::append(&mut msg, report);
        let msg = blake2b_256(msg);

        let signatures = vector[];
        let required_signatures = config.f + 1;
        for (i in 0..required_signatures) {
            let signer = vector::borrow(&config.signers, (i as u64));
            let public_key = ed25519::new_unvalidated_public_key_from_bytes(*vector::borrow(&config.oracles, (i as u64)));
            let sig = ed25519::sign_arbitrary_bytes(signer, msg);
            vector::push_back(&mut signatures, Signature {
                sig,
                public_key,
            });
        };
        signatures
    }

    #[test (
        owner = @0xcafe,
        account = @keystone,
    )]
    public entry fun test_happy_path(
        owner: signer,
        account: signer,
    ) acquires State {
        set_up_test(&owner, &account);

        let config = generate_oracle_set();

        // configure DON
        set_config(&owner, config.don_id, config.config_version, config.f, config.oracles);

        // generate report
        let version = 1;
        let timestamp: u32 = 1;
        let workflow_id = x"6d795f6964000000000000000000000000000000000000000000000000000000";
        let workflow_name = x"000000000000DEADBEEF";
        let workflow_owner = x"0000000000000000000000000000000000000051";
        let report_id = x"0001";
        let execution_id = x"6d795f657865637574696f6e5f69640000000000000000000000000000000000";
        let mercury_reports = vector[x"010203", x"aabbcc"];

        let report = vector[];
        // header
        vector::push_back(&mut report, version);
        vector::append(&mut report, execution_id);

        let bytes = bcs::to_bytes(&timestamp);
        // convert little-endian to big-endian
        vector::reverse(&mut bytes);
        vector::append(&mut report, bytes);

        let bytes = bcs::to_bytes(&config.don_id);
        // convert little-endian to big-endian
        vector::reverse(&mut bytes);
        vector::append(&mut report, bytes);

        let bytes = bcs::to_bytes(&config.config_version);
        // convert little-endian to big-endian
        vector::reverse(&mut bytes);
        vector::append(&mut report, bytes);

        // metadata
        vector::append(&mut report, workflow_id);
        vector::append(&mut report, workflow_name);
        vector::append(&mut report, workflow_owner);
        vector::append(&mut report, report_id);
        // report
        vector::append(&mut report, bcs::to_bytes(&mercury_reports));

        let report_context = x"a0b0000000000000000000000000000000000000000000000000000000000000";

        // sign report
        let signatures = sign_report(&config, report, report_context);

        // call entrypoint
        validate_report(&owner, signer::address_of(&account), report, report_context, signatures);
    }
}
