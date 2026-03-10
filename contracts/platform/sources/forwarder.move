module platform::forwarder {
    use aptos_framework::object::{Self, ExtendRef, TransferRef};
    use aptos_std::smart_table::{SmartTable, Self};

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
    const E_NOT_OWNER: u64 = 7;
    const E_MALFORMED_SIGNATURE: u64 = 8;
    const E_FAULT_TOLERANCE_MUST_BE_POSITIVE: u64 = 9;
    const E_EXCESS_SIGNERS: u64 = 10;
    const E_INSUFFICIENT_SIGNERS: u64 = 11;
    const E_CALLBACK_DATA_NOT_CONSUMED: u64 = 12;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 13;
    const E_NOT_PROPOSED_OWNER: u64 = 14;
    const E_CONFIG_ID_NOT_FOUND: u64 = 15;
    const E_INVALID_REPORT_VERSION: u64 = 16;

    const MAX_ORACLES: u64 = 31;

    const APP_OBJECT_SEED: vector<u8> = b"FORWARDER";

    struct ConfigId has key, store, drop, copy {
        don_id: u32,
        config_version: u32
    }

    struct State has key {
        owner_address: address,
        pending_owner_address: address,
        extend_ref: ExtendRef,
        transfer_ref: TransferRef,

        // (don_id, config_version) => config
        configs: SmartTable<ConfigId, Config>,
        reports: SmartTable<vector<u8>, address>
    }

    struct Config has key, store, drop, copy {
        f: u8,
        // oracles: SimpleMap<address, Oracle>,
        oracles: vector<ed25519::UnvalidatedPublicKey>
    }

    #[event]
    struct ConfigSet has drop, store {
        don_id: u32,
        config_version: u32,
        f: u8,
        signers: vector<vector<u8>>
    }

    #[event]
    struct ReportProcessed has drop, store {
        receiver: address,
        workflow_execution_id: vector<u8>,
        report_id: u16
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

    inline fun assert_is_owner(state: &State, target_address: address) {
        assert!(
            state.owner_address == target_address,
            error::permission_denied(E_NOT_OWNER)
        );
    }

    fun init_module(publisher: &signer) {
        assert!(signer::address_of(publisher) == @platform, 1);

        let constructor_ref = object::create_named_object(publisher, APP_OBJECT_SEED);

        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let app_signer = &object::generate_signer(&constructor_ref);

        move_to(
            app_signer,
            State {
                owner_address: @owner,
                pending_owner_address: @0x0,
                configs: smart_table::new(),
                reports: smart_table::new(),
                extend_ref,
                transfer_ref
            }
        );
    }

    inline fun get_state_addr(): address {
        object::create_object_address(&@platform, APP_OBJECT_SEED)
    }

    public entry fun set_config(
        authority: &signer,
        don_id: u32,
        config_version: u32,
        f: u8,
        oracles: vector<vector<u8>>
    ) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());

        assert_is_owner(state, signer::address_of(authority));

        assert!(f != 0, error::invalid_argument(E_FAULT_TOLERANCE_MUST_BE_POSITIVE));
        assert!(
            vector::length(&oracles) <= MAX_ORACLES,
            error::invalid_argument(E_EXCESS_SIGNERS)
        );
        assert!(
            vector::length(&oracles) >= 3 * (f as u64) + 1,
            error::invalid_argument(E_INSUFFICIENT_SIGNERS)
        );

        smart_table::upsert(
            &mut state.configs,
            ConfigId { don_id, config_version },
            Config {
                f,
                oracles: vector::map(
                    oracles,
                    |oracle| {
                        ed25519::new_unvalidated_public_key_from_bytes(oracle)
                    }
                )
            }
        );

        event::emit(
            ConfigSet { don_id, config_version, f, signers: oracles }
        );
    }

    public entry fun clear_config(
        authority: &signer, don_id: u32, config_version: u32
    ) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());

        assert_is_owner(state, signer::address_of(authority));

        smart_table::remove(&mut state.configs, ConfigId { don_id, config_version });

        event::emit(
            ConfigSet {
                don_id,
                config_version,
                f: 0,
                signers: vector::empty()
            }
        );
    }

    use aptos_std::aptos_hash::blake2b_256;
    use aptos_std::ed25519;

    struct Signature has drop {
        public_key: ed25519::UnvalidatedPublicKey, // TODO: pass signer index rather than key to save on space and gas?
        sig: ed25519::Signature
    }

    public fun signature_from_bytes(bytes: vector<u8>): Signature {
        assert!(
            vector::length(&bytes) == 96,
            error::invalid_argument(E_MALFORMED_SIGNATURE)
        );
        let public_key =
            ed25519::new_unvalidated_public_key_from_bytes(vector::slice(&bytes, 0, 32));
        let sig = ed25519::new_signature_from_bytes(vector::slice(&bytes, 32, 96));
        Signature { sig, public_key }
    }

    inline fun transmission_id(
        receiver: address, workflow_execution_id: vector<u8>, report_id: u16
    ): vector<u8> {
        let id = bcs::to_bytes(&receiver);
        vector::append(&mut id, workflow_execution_id);
        vector::append(&mut id, bcs::to_bytes(&report_id));
        id
    }

    /// The dispatch call knows both storage and indirectly the callback, thus the separate module.
    fun dispatch(receiver: address, metadata: vector<u8>, data: vector<u8>) {
        let meta = platform::storage::insert(receiver, metadata, data);
        aptos_framework::dispatchable_fungible_asset::derived_supply(meta);
        let obj_address =
            object::object_address<aptos_framework::fungible_asset::Metadata>(&meta);
        assert!(
            !platform::storage::storage_exists(obj_address),
            E_CALLBACK_DATA_NOT_CONSUMED
        );
    }

    entry fun report(
        transmitter: &signer,
        receiver: address,
        raw_report: vector<u8>,
        signatures: vector<vector<u8>>
    ) acquires State {
        let signatures = vector::map(
            signatures, |signature| signature_from_bytes(signature)
        );

        let (metadata, data) =
            validate_and_process_report(transmitter, receiver, raw_report, signatures);
        // NOTE: unable to catch failure here
        dispatch(receiver, metadata, data);
    }

    inline fun to_u16be(data: vector<u8>): u16 {
        // reverse big endian to little endian
        vector::reverse(&mut data);
        aptos_std::from_bcs::to_u16(data)
    }

    inline fun to_u32be(data: vector<u8>): u32 {
        // reverse big endian to little endian
        vector::reverse(&mut data);
        aptos_std::from_bcs::to_u32(data)
    }

    fun validate_and_process_report(
        transmitter: &signer,
        receiver: address,
        raw_report: vector<u8>,
        signatures: vector<Signature>
    ): (vector<u8>, vector<u8>) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());

        // report_context = vector::slice(&raw_report, 0, 96);
        let report = vector::slice(&raw_report, 96, vector::length(&raw_report));

        // parse out report metadata
        // version | workflow_execution_id | timestamp | don_id | config_version | ...
        let report_version = *vector::borrow(&report, 0);
        assert!(report_version == 1, E_INVALID_REPORT_VERSION);

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

        let config_id = ConfigId { don_id, config_version };
        assert!(smart_table::contains(&state.configs, config_id), E_CONFIG_ID_NOT_FOUND);
        let config = smart_table::borrow(&state.configs, config_id);

        // check if report was already delivered
        let transmission_id = transmission_id(receiver, workflow_execution_id, report_id);
        let processed = smart_table::contains(&state.reports, transmission_id);
        assert!(!processed, E_ALREADY_PROCESSED);

        let required_signatures = (config.f as u64) + 1;
        assert!(
            vector::length(&signatures) == required_signatures,
            error::invalid_argument(E_INVALID_SIGNATURE_COUNT)
        );

        // blake2b(report_context | report)
        let msg = blake2b_256(raw_report);

        let signed = bit_vector::new(vector::length(&config.oracles));

        vector::for_each_ref(
            &signatures,
            |signature| {
                let signature: &Signature = signature; // some compiler versions can't infer the type here

                let (valid, index) = vector::index_of(
                    &config.oracles, &signature.public_key
                );
                assert!(valid, error::invalid_argument(E_INVALID_SIGNER));

                // check for duplicate signers
                let duplicate = bit_vector::is_index_set(&signed, index);
                assert!(!duplicate, error::invalid_argument(E_DUPLICATE_SIGNER));
                bit_vector::set(&mut signed, index);

                let result =
                    ed25519::signature_verify_strict(
                        &signature.sig, &signature.public_key, msg
                    );
                assert!(result, error::invalid_argument(E_INVALID_SIGNATURE));
            }
        );

        // mark as delivered
        smart_table::add(
            &mut state.reports,
            transmission_id,
            signer::address_of(transmitter)
        );

        event::emit(ReportProcessed { receiver, workflow_execution_id, report_id });

        (metadata, data)
    }

    #[view]
    public fun get_transmission_state(
        receiver: address, workflow_execution_id: vector<u8>, report_id: u16
    ): bool acquires State {
        let state = borrow_global<State>(get_state_addr());
        let transmission_id = transmission_id(receiver, workflow_execution_id, report_id);

        return smart_table::contains(&state.reports, transmission_id)
    }

    #[view]
    public fun get_transmitter(
        receiver: address, workflow_execution_id: vector<u8>, report_id: u16
    ): Option<address> acquires State {
        let state = borrow_global<State>(get_state_addr());
        let transmission_id = transmission_id(receiver, workflow_execution_id, report_id);

        if (!smart_table::contains(&state.reports, transmission_id)) {
            return option::none()
        };
        option::some(*smart_table::borrow(&state.reports, transmission_id))
    }

    // Ownership functions
    #[view]
    public fun get_owner(): address acquires State {
        let state = borrow_global<State>(get_state_addr());
        state.owner_address
    }

    #[view]
    public fun get_config(don_id: u32, config_version: u32): Config acquires State {
        let state = borrow_global<State>(get_state_addr());
        let config_id = ConfigId { don_id, config_version };
        *smart_table::borrow(&state.configs, config_id)
    }

    public entry fun transfer_ownership(authority: &signer, to: address) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());
        assert_is_owner(state, signer::address_of(authority));
        assert!(
            state.owner_address != to,
            error::invalid_argument(E_CANNOT_TRANSFER_TO_SELF)
        );

        state.pending_owner_address = to;

        event::emit(OwnershipTransferRequested { from: state.owner_address, to });
    }

    public entry fun accept_ownership(authority: &signer) acquires State {
        let state = borrow_global_mut<State>(get_state_addr());
        assert!(
            state.pending_owner_address == signer::address_of(authority),
            error::permission_denied(E_NOT_PROPOSED_OWNER)
        );

        let old_owner_address = state.owner_address;
        state.owner_address = state.pending_owner_address;
        state.pending_owner_address = @0x0;

        event::emit(
            OwnershipTransferred { from: old_owner_address, to: state.owner_address }
        );
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public entry fun set_up_test(owner: &signer, publisher: &signer) {
        use aptos_framework::account::{Self};
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(publisher));

        init_module(publisher);
    }

    #[test_only]
    struct OracleSet has drop {
        don_id: u32,
        config_version: u32,
        f: u8,
        oracles: vector<vector<u8>>,
        signers: vector<ed25519::SecretKey>
    }

    #[test_only]
    fun generate_oracle_set(): OracleSet {
        generate_oracle_set_with_params(0, 1, 1, 31)
    }

    #[test_only]
    fun generate_oracle_set_with_params(
        don_id: u32, config_version: u32, f: u8, num_oracles: u64
    ): OracleSet {
        let signers = vector[];
        let oracles = vector[];
        for (_i in 0..num_oracles) {
            let (sk, pk) = ed25519::generate_keys();
            vector::push_back(&mut signers, sk);
            vector::push_back(&mut oracles, ed25519::validated_public_key_to_bytes(&pk));
        };
        OracleSet { don_id, config_version, f, oracles, signers }
    }

    #[test_only]
    fun sign_report_n(
        config: &OracleSet, report: vector<u8>, report_context: vector<u8>, n: u8
    ): vector<Signature> {
        let msg = report_context;
        vector::append(&mut msg, report);
        let msg = blake2b_256(msg);

        let signatures = vector[];
        for (i in 0..n) {
            let config_signer = vector::borrow(&config.signers, (i as u64));
            let public_key =
                ed25519::new_unvalidated_public_key_from_bytes(
                    *vector::borrow(&config.oracles, (i as u64))
                );
            let sig = ed25519::sign_arbitrary_bytes(config_signer, msg);
            vector::push_back(&mut signatures, Signature { sig, public_key });
        };
        signatures
    }

    #[test_only]
    fun sign_report(
        config: &OracleSet, report: vector<u8>, report_context: vector<u8>
    ): vector<Signature> {
        sign_report_n(config, report, report_context, config.f + 1)
    }

    #[test_only]
    fun build_report_with_overrides(
        version: u8, don_id: u32, config_version: u32, execution_id: vector<u8>
    ): (vector<u8>, vector<u8>, vector<u8>) {
        let timestamp: u32 = 1;
        let workflow_id =
            x"6d795f6964000000000000000000000000000000000000000000000000000000";
        let workflow_name = x"000000000000DEADBEEF";
        let workflow_owner = x"0000000000000000000000000000000000000051";
        let report_id = x"0001";
        let mercury_reports = vector[x"010203", x"aabbcc"];

        let report = vector[];
        vector::push_back(&mut report, version);
        vector::append(&mut report, execution_id);

        let bytes = bcs::to_bytes(&timestamp);
        vector::reverse(&mut bytes);
        vector::append(&mut report, bytes);

        let bytes = bcs::to_bytes(&don_id);
        vector::reverse(&mut bytes);
        vector::append(&mut report, bytes);

        let bytes = bcs::to_bytes(&config_version);
        vector::reverse(&mut bytes);
        vector::append(&mut report, bytes);

        vector::append(&mut report, workflow_id);
        vector::append(&mut report, workflow_name);
        vector::append(&mut report, workflow_owner);
        vector::append(&mut report, report_id);
        vector::append(&mut report, bcs::to_bytes(&mercury_reports));

        let report_context =
            x"a0b000000000000000000000000000000000000000000000000000000000000a0b000000000000000000000000000000000000000000000000000000000000a0b000000000000000000000000000000000000000000000000000000000000000";

        let raw_report = vector[];
        vector::append(&mut raw_report, copy report_context);
        vector::append(&mut raw_report, copy report);

        (raw_report, report, report_context)
    }

    #[test_only]
    fun build_report(config: &OracleSet): (vector<u8>, vector<u8>, vector<u8>) {
        build_report_with_overrides(
            1,
            config.don_id,
            config.config_version,
            x"6d795f657865637574696f6e5f69640000000000000000000000000000000000"
        )
    }

    #[test(owner = @owner, publisher = @platform)]
    public entry fun test_happy_path(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, report, report_context) = build_report(&config);
        let signatures = sign_report(&config, report, report_context);

        let receiver = signer::address_of(publisher);
        let execution_id =
            x"6d795f657865637574696f6e5f69640000000000000000000000000000000000";
        let report_id: u16 = 1;

        assert!(
            !get_transmission_state(receiver, execution_id, report_id),
            1
        );

        validate_and_process_report(owner, receiver, raw_report, signatures);

        assert!(
            get_transmission_state(receiver, execution_id, report_id),
            2
        );
        let transmitter = get_transmitter(receiver, execution_id, report_id);
        assert!(*option::borrow(&transmitter) == signer::address_of(owner), 3);
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 15, location = platform::forwarder)]
    fun test_report_incorrect_don(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, report, report_context) =
            build_report_with_overrides(
                1,
                999,
                config.config_version,
                x"6d795f657865637574696f6e5f69640000000000000000000000000000000000"
            );
        let signatures = sign_report(&config, report, report_context);

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 15, location = platform::forwarder)]
    fun test_report_inexistent_config_version(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, report, report_context) =
            build_report_with_overrides(
                1,
                config.don_id,
                config.config_version + 1,
                x"6d795f657865637574696f6e5f69640000000000000000000000000000000000"
            );
        let signatures = sign_report(&config, report, report_context);

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure]
    fun test_report_malformed(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let raw_report = x"deadbeef";
        let signatures: vector<Signature> = vector[];

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65540, location = platform::forwarder)]
    fun test_report_too_few_signatures(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, report, report_context) = build_report(&config);
        let signatures = sign_report_n(&config, report, report_context, config.f);

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65540, location = platform::forwarder)]
    fun test_report_too_many_signatures(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, report, report_context) = build_report(&config);
        let signatures = sign_report_n(&config, report, report_context, config.f + 2);

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65541, location = platform::forwarder)]
    fun test_report_invalid_signature(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, _report, _report_context) = build_report(&config);
        let msg = blake2b_256(copy raw_report);

        // Valid signature from signer 0
        let pk0 =
            ed25519::new_unvalidated_public_key_from_bytes(
                *vector::borrow(&config.oracles, 0)
            );
        let sig0 = ed25519::sign_arbitrary_bytes(vector::borrow(&config.signers, 0), msg);

        // Signer 1's public key paired with signer 0's signature
        let pk1 =
            ed25519::new_unvalidated_public_key_from_bytes(
                *vector::borrow(&config.oracles, 1)
            );
        let bad_sig =
            ed25519::sign_arbitrary_bytes(vector::borrow(&config.signers, 0), msg);

        let signatures = vector[
            Signature { sig: sig0, public_key: pk0 },
            Signature { sig: bad_sig, public_key: pk1 }
        ];

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65538, location = platform::forwarder)]
    fun test_report_invalid_signer(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, _report, _report_context) = build_report(&config);
        let msg = blake2b_256(copy raw_report);

        // Valid signature from signer 0
        let pk0 =
            ed25519::new_unvalidated_public_key_from_bytes(
                *vector::borrow(&config.oracles, 0)
            );
        let sig0 = ed25519::sign_arbitrary_bytes(vector::borrow(&config.signers, 0), msg);

        // Unknown signer not in config
        let (unknown_sk, unknown_pk) = ed25519::generate_keys();
        let unknown_pk =
            ed25519::new_unvalidated_public_key_from_bytes(
                ed25519::validated_public_key_to_bytes(&unknown_pk)
            );
        let unknown_sig = ed25519::sign_arbitrary_bytes(&unknown_sk, msg);

        let signatures = vector[
            Signature { sig: sig0, public_key: pk0 },
            Signature { sig: unknown_sig, public_key: unknown_pk }
        ];

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65539, location = platform::forwarder)]
    fun test_report_duplicate_signatures(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, _report, _report_context) = build_report(&config);
        let msg = blake2b_256(copy raw_report);

        // Same signer twice
        let pk0a =
            ed25519::new_unvalidated_public_key_from_bytes(
                *vector::borrow(&config.oracles, 0)
            );
        let sig0a = ed25519::sign_arbitrary_bytes(
            vector::borrow(&config.signers, 0), msg
        );
        let pk0b =
            ed25519::new_unvalidated_public_key_from_bytes(
                *vector::borrow(&config.oracles, 0)
            );
        let sig0b = ed25519::sign_arbitrary_bytes(
            vector::borrow(&config.signers, 0), msg
        );

        let signatures = vector[
            Signature { sig: sig0a, public_key: pk0a },
            Signature { sig: sig0b, public_key: pk0b }
        ];

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 6, location = platform::forwarder)]
    fun test_report_already_processed(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        // First submission succeeds
        let (raw_report, report, report_context) = build_report(&config);
        let signatures = sign_report(&config, report, report_context);
        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );

        // Second submission with same report fails
        let (raw_report2, report2, report_context2) = build_report(&config);
        let signatures2 = sign_report(&config, report2, report_context2);
        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report2,
            signatures2
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 16, location = platform::forwarder)]
    fun test_report_invalid_version(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let (raw_report, report, report_context) =
            build_report_with_overrides(
                2,
                config.don_id,
                config.config_version,
                x"6d795f657865637574696f6e5f69640000000000000000000000000000000000"
            );
        let signatures = sign_report(&config, report, report_context);

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test]
    #[expected_failure(abort_code = 65544, location = platform::forwarder)]
    fun test_report_malformed_signature() {
        signature_from_bytes(
            x"0102030405060708091011121314151617181920212223242526272829303132"
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 15, location = platform::forwarder)]
    fun test_report_after_clear_config(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set();
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );
        clear_config(owner, config.don_id, config.config_version);

        let (raw_report, report, report_context) = build_report(&config);
        let signatures = sign_report(&config, report, report_context);

        validate_and_process_report(
            owner,
            signer::address_of(publisher),
            raw_report,
            signatures
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_report_config_version_lifecycle(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config_v1 = generate_oracle_set();
        let config_v2 = generate_oracle_set();
        config_v2.config_version = 2;

        set_config(
            owner,
            config_v1.don_id,
            config_v1.config_version,
            config_v1.f,
            config_v1.oracles
        );
        set_config(
            owner,
            config_v2.don_id,
            config_v2.config_version,
            config_v2.f,
            config_v2.oracles
        );

        // Report on v1 succeeds
        let (raw_report_v1, report_v1, report_context_v1) = build_report(&config_v1);
        let signatures_v1 = sign_report(&config_v1, report_v1, report_context_v1);
        let receiver = signer::address_of(publisher);
        validate_and_process_report(owner, receiver, raw_report_v1, signatures_v1);

        // Verify transmitter recorded for v1
        let execution_id =
            x"6d795f657865637574696f6e5f69640000000000000000000000000000000000";
        let report_id: u16 = 1;
        assert!(
            get_transmission_state(receiver, execution_id, report_id),
            1
        );
        assert!(
            *option::borrow(&get_transmitter(receiver, execution_id, report_id))
                == signer::address_of(owner),
            2
        );

        // Clear config v1
        clear_config(owner, config_v1.don_id, config_v1.config_version);

        // Report on v2 succeeds (v2 unaffected by v1 clear)
        let new_execution_id =
            x"6d795f657865637574696f6e5f69640000000000000000000000000000000001";
        let (raw_report_v2, report_v2, report_context_v2) =
            build_report_with_overrides(
                1,
                config_v2.don_id,
                config_v2.config_version,
                new_execution_id
            );
        let signatures_v2 = sign_report(&config_v2, report_v2, report_context_v2);
        validate_and_process_report(owner, receiver, raw_report_v2, signatures_v2);

        // Verify transmitter recorded for v2
        assert!(
            get_transmission_state(receiver, new_execution_id, report_id),
            3
        );
        assert!(
            *option::borrow(&get_transmitter(receiver, new_execution_id, report_id))
                == signer::address_of(owner),
            4
        );
    }

    #[test(owner = @owner, publisher = @platform, new_owner = @0xbeef)]
    fun test_transfer_ownership_success(
        owner: &signer, publisher: &signer, new_owner: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(owner, signer::address_of(new_owner));
        accept_ownership(new_owner);

        assert!(get_owner() == signer::address_of(new_owner), 2);
    }

    #[test(owner = @owner, publisher = @platform, unknown_user = @0xbeef)]
    #[expected_failure(abort_code = 327687, location = platform::forwarder)]
    fun test_transfer_ownership_failure_not_owner(
        owner: &signer, publisher: &signer, unknown_user: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(unknown_user, signer::address_of(unknown_user));
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65549, location = platform::forwarder)]
    fun test_transfer_ownership_failure_transfer_to_self(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(owner, signer::address_of(owner));
    }

    #[test(owner = @owner, publisher = @platform, new_owner = @0xbeef)]
    #[expected_failure(abort_code = 327694, location = platform::forwarder)]
    fun test_transfer_ownership_failure_not_proposed_owner(
        owner: &signer, publisher: &signer, new_owner: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        assert!(get_owner() == @owner, 1);

        transfer_ownership(owner, @0xfeeb);
        accept_ownership(new_owner);
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_set_config_success(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let stored = get_config(1, 1);
        assert!(stored.f == 1, 1);
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_set_config_success_max_oracles(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        // MAX_ORACLES = 31, f=10 requires 3*10+1 = 31 oracles
        let config = generate_oracle_set_with_params(1, 1, 10, 31);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        let stored = get_config(1, 1);
        assert!(stored.f == 10, 1);
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_set_config_success_upsert(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        // Set initial config with f=1
        let config1 = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config1.don_id,
            config1.config_version,
            config1.f,
            config1.oracles
        );

        let stored = get_config(1, 1);
        assert!(stored.f == 1, 1);

        // Overwrite same don_id/config_version with f=2
        let config2 = generate_oracle_set_with_params(1, 1, 2, 7);
        set_config(
            owner,
            config2.don_id,
            config2.config_version,
            config2.f,
            config2.oracles
        );

        let stored = get_config(1, 1);
        assert!(stored.f == 2, 2);
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_set_config_success_multiple_dons(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config1 = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config1.don_id,
            config1.config_version,
            config1.f,
            config1.oracles
        );

        let config2 = generate_oracle_set_with_params(2, 1, 2, 7);
        set_config(
            owner,
            config2.don_id,
            config2.config_version,
            config2.f,
            config2.oracles
        );

        let stored1 = get_config(1, 1);
        assert!(stored1.f == 1, 1);

        let stored2 = get_config(2, 1);
        assert!(stored2.f == 2, 2);
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_set_config_success_multiple_versions(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config1 = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config1.don_id,
            config1.config_version,
            config1.f,
            config1.oracles
        );

        let config2 = generate_oracle_set_with_params(1, 2, 2, 7);
        set_config(
            owner,
            config2.don_id,
            config2.config_version,
            config2.f,
            config2.oracles
        );

        let stored1 = get_config(1, 1);
        assert!(stored1.f == 1, 1);

        let stored2 = get_config(1, 2);
        assert!(stored2.f == 2, 2);
    }

    #[test(owner = @owner, publisher = @platform, unknown_user = @0xbeef)]
    #[expected_failure(abort_code = 327687, location = platform::forwarder)]
    fun test_set_config_failure_not_owner(
        owner: &signer, publisher: &signer, unknown_user: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            unknown_user,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65545, location = platform::forwarder)]
    fun test_set_config_failure_f_is_zero(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set_with_params(1, 1, 0, 4);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            0,
            config.oracles
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65546, location = platform::forwarder)]
    fun test_set_config_failure_too_many_oracles(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        // 32 oracles exceeds MAX_ORACLES (31)
        let config = generate_oracle_set_with_params(1, 1, 1, 32);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65547, location = platform::forwarder)]
    fun test_set_config_failure_insufficient_oracles(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        // f=1 requires 3*1+1 = 4 oracles, but only 3 provided
        let config = generate_oracle_set_with_params(1, 1, 1, 3);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure(abort_code = 65547, location = platform::forwarder)]
    fun test_set_config_failure_insufficient_oracles_higher_f(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        // f=5 requires 3*5+1 = 16 oracles, but only 15 provided
        let config = generate_oracle_set_with_params(1, 1, 5, 15);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_clear_config_success(owner: &signer, publisher: &signer) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        // Verify config exists
        let stored = get_config(1, 1);
        assert!(stored.f == 1, 1);

        // Clear config
        clear_config(owner, 1, 1);
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure]
    fun test_clear_config_get_after_clear(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        clear_config(owner, 1, 1);

        // Should abort: config no longer exists
        get_config(1, 1);
    }

    #[test(owner = @owner, publisher = @platform)]
    fun test_clear_config_does_not_affect_other_configs(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config1 = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config1.don_id,
            config1.config_version,
            config1.f,
            config1.oracles
        );

        let config2 = generate_oracle_set_with_params(2, 1, 2, 7);
        set_config(
            owner,
            config2.don_id,
            config2.config_version,
            config2.f,
            config2.oracles
        );

        // Clear only DON 1
        clear_config(owner, 1, 1);

        // DON 2 should still exist
        let stored = get_config(2, 1);
        assert!(stored.f == 2, 1);
    }

    #[test(owner = @owner, publisher = @platform, unknown_user = @0xbeef)]
    #[expected_failure(abort_code = 327687, location = platform::forwarder)]
    fun test_clear_config_failure_not_owner(
        owner: &signer, publisher: &signer, unknown_user: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        let config = generate_oracle_set_with_params(1, 1, 1, 4);
        set_config(
            owner,
            config.don_id,
            config.config_version,
            config.f,
            config.oracles
        );

        clear_config(unknown_user, 1, 1);
    }

    #[test(owner = @owner, publisher = @platform)]
    #[expected_failure]
    fun test_clear_config_failure_nonexistent(
        owner: &signer, publisher: &signer
    ) acquires State {
        set_up_test(owner, publisher);

        // Clear config that was never set
        clear_config(owner, 99, 99);
    }
}
