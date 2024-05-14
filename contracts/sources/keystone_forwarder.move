module chainlink::keystone_forwarder {
    use aptos_framework::account::{Self, SignerCapability};
    use aptos_framework::resource_account;
    use std::error;
    use std::event;
    use std::vector;
    use std::bit_vector;
    use std::option::{Self, Option};
    use std::signer;
    use std::bcs;

    const E_ACCOUNT_NOT_REGISTERED: u64 = 0;
    const E_INVALID_DATA_LENGTH: u64 = 1;
    const E_INVALID_SIGNER: u64 = 2;
    const E_DUPLICATE_SIGNER: u64 = 3;
    const E_INVALID_SIGNATURE_COUNT: u64 = 4;
    const E_INVALID_SIGNATURE: u64 = 5;
    const E_ALREADY_PROCESSED: u64 = 6;

    struct Receiver has key {
        signer_cap: account::SignerCapability
    }

    struct Mailbox has key, drop {
        report: vector<u8>
    }

    /// To generate resource account
    const RECEIVER_SEED: vector<u8> = b"receiver";

    public entry fun register(receiver: &signer) {
        let (resource_account, signer_cap) = account::create_resource_account(receiver, RECEIVER_SEED);
        let state = Receiver { signer_cap };
        move_to(receiver, state)
    }

    #[view]
    /// Returns `true` if `account_addr` is registered to receive Keystone report.
    public fun is_account_registered(account_addr: address): bool {
        exists<Mailbox>(account_addr)
    }

    public entry fun transmit(receiver: address, data: vector<u8>, signatures: vector<u8>) acquires Receiver {
        // TODO: check for resource account
        // if (!account::exists_at(receiver)) {
        //  account::create_account(receiver);
        // };

        // TODO: check mailbox doesn't exist, if it does clear it first
        assert!(
            !is_account_registered(receiver),
            error::not_found(E_ACCOUNT_NOT_REGISTERED),
        );

        let mailbox = Mailbox { report: data }; // TODO: subset of data

        let state = borrow_global<Receiver>(receiver);
        let resource_signer = account::create_signer_with_capability(&state.signer_cap);
        move_to(&resource_signer, mailbox)
    }

    /// Called by the receiver module to fetch the report that was stored by the transmitter. This must be executed within a Move script together with transmit() so the operation is atomic!
    public fun consume_report(receiver: &signer): vector<u8> acquires Receiver, Mailbox {
        let state = borrow_global<Receiver>(signer::address_of(receiver));

        let resource_signer = account::create_signer_with_capability(&state.signer_cap);

        // TODO: have receiver be signer, then fetch resource_account for the signer
        move_from<Mailbox>(signer::address_of(&resource_signer)).report
    }

    // 

    use aptos_std::smart_table::{SmartTable,Self};

    struct State has key {
        signer_cap: SignerCapability,
        // don_id => config
        configs: SmartTable<u32, Config>,

        reports: SmartTable<vector<u8>, address>
    }

    struct Config has key, store, drop {
        f: u8,
        // oracles: SimpleMap<address, Oracle>,
        oracles: vector<ed25519::UnvalidatedPublicKey>,
    }

    #[event]
    struct ReportProcessed has drop, store {
        receiver: address,
        workflow_owner: vector<u8>,
        workflow_execution_id: vector<u8>,
    }

    fun init_module(resource_signer: &signer) {
        // TODO: save owner

        let signer_cap = resource_account::retrieve_resource_account_cap(resource_signer, @deployer);

        move_to(resource_signer, State {
            configs: smart_table::new(),
            reports: smart_table::new(),
            signer_cap,
        });
    }

    public entry fun set_config(don_id: u32, f: u8, oracles: vector<vector<u8>>) acquires State {
        let state = borrow_global_mut<State>(@forwarder);
        // TODO: assert owner
        smart_table::upsert(&mut state.configs, don_id, Config {
            f,
            oracles: vector::map(oracles, |oracle| {
                ed25519::new_unvalidated_public_key_from_bytes(oracle)
            })
        });
    }

    use aptos_std::aptos_hash::keccak256;
    use aptos_std::ed25519;

    struct Signature has drop {
        sig: ed25519::Signature,
        public_key: ed25519::UnvalidatedPublicKey, // TODO: pass signer index rather than key to save on space and gas
    }

    inline fun report_id(receiver: address, workflow_execution_id: vector<u8>): vector<u8> {
        let id = vector[];
        vector::append(&mut id, bcs::to_bytes(&receiver));
        vector::append(&mut id, workflow_execution_id);
        // TODO: spec to assert on key lengths
        id
    }

    // receiver_authority is a resource account owned by the receiver
    // TODO: a method to register these accounts
    public fun validate_report(receiver_authority: &signer, report: vector<u8>, signatures: vector<Signature>) acquires State {
        let state = borrow_global_mut<State>(@forwarder);

        // parse out report metadata
        // workflow_id | don_id | workflow_execution_id | workflow_owner
        let workflow_id = vector::slice(&report, 0, 32);
        let don_id = vector::slice(&report, 32, 36);
        let don_id = aptos_std::from_bcs::to_u32(don_id);
        let workflow_execution_id = vector::slice(&report, 36, 58);
        let workflow_owner = vector::slice(&report, 58, 78);

        // this will revert if don_id doesn't exist
        let config = smart_table::borrow(&state.configs, don_id);

        // check if report was already delivered
        let report_id = report_id(signer::address_of(receiver_authority), workflow_execution_id);
        let processed = smart_table::contains(&state.reports, report_id);
        assert!(!processed, E_ALREADY_PROCESSED);

        let required_signatures = (config.f as u64) + 1;
        assert!(vector::length(&signatures) == required_signatures, error::invalid_argument(E_INVALID_SIGNATURE_COUNT));

        let msg = keccak256(report);

        let signed = bit_vector::new(vector::length(&signatures));

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

        let receiver = signer::address_of(receiver_authority);
        // mark as delivered
        // TODO: can't have transmitter address since passed through receiver -> receiver has to be called
        // without signer
        smart_table::add(&mut state.reports, report_id, receiver);

        event::emit(ReportProcessed {
            receiver,
            workflow_owner,
            workflow_execution_id,
        })
    }

    public fun get_transmitter(receiver: address, workflow_execution_id: vector<u8>): Option<address> acquires State {
        let state = borrow_global_mut<State>(@forwarder);
        let report_id = report_id(receiver, workflow_execution_id);

        if (!smart_table::contains(&mut state.reports, report_id)) {
            return option::none()
        };
        option::some(*smart_table::borrow(&mut state.reports, report_id))
    }

    #[test_only]
    public entry fun set_up_test(deployer: &signer, resource_account: &signer) {
        use std::vector;

        account::create_account_for_test(signer::address_of(deployer));

        // create a resource account from the origin account, mocking the module publishing process
        resource_account::create_resource_account(deployer, vector::empty<u8>(), vector::empty<u8>());
        init_module(resource_account);
    }

    #[test (
        deployer = @0xcafe,
        forwarder = @0xc3bb8488ab1a5815a9d543d7e41b0e0df46a7396f89b22821f07a4362f75ddc5,
        // aptos_framework = @aptos_framework
    )]
    public entry fun test_happy_path(
        deployer: signer,
        forwarder: signer,
        // aptos_framework: signer
    ) acquires State {
        set_up_test(&deployer, &forwarder);

        let don_id = 0;
        let f = 1;

        // generate oracle set
        let signers = vector[];
        let oracles = vector[];
        for (i in 0..31) {
            let (sk, pk) = ed25519::generate_keys();
            vector::push_back(&mut signers, sk);
            vector::push_back(&mut oracles, ed25519::validated_public_key_to_bytes(&pk));
        };

        // configure DON
        set_config(don_id, f, oracles);

        // generate report
        let workflow_id = x"6d795f6964000000000000000000000000000000000000000000000000000000";
        let workflow_owner = x"0000000000000000000000000000000000000051";
        let execution_id = x"6d795f657865637574696f6e5f69640000000000000000000000000000000000";
        let mercury_reports = vector[x"010203", x"aabbcc"];

        let report = vector[];
        vector::append(&mut report, workflow_id);
        vector::append(&mut report, bcs::to_bytes(&don_id));
        vector::append(&mut report, execution_id);
        vector::append(&mut report, workflow_owner);

        // sign report
        let msg = keccak256(report);
        let signatures = vector[];
        let required_signatures = f + 1;
        for (i in 0..required_signatures) {
            let signer = vector::borrow(&signers, (i as u64));
            let public_key = ed25519::new_unvalidated_public_key_from_bytes(*vector::borrow(&oracles, (i as u64)));
            let sig = ed25519::sign_arbitrary_bytes(signer, msg);
            vector::push_back(&mut signatures, Signature {
                sig,
                public_key,
            });
        };

        // call entrypoint
        validate_report(&deployer, report, signatures);
    }
}
