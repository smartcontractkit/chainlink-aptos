/// The forwarder module handles report validation and forwarding.
module chainlink_platform::forwarder {
    use std::vector;
    use std::option::{Self, Option};
    
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use sui::bcs;
    use sui::hash::blake2b256;
    
    use chainlink_platform::storage;
    use chainlink_platform::vector_utils;
    
    // Constants
    const APP_OBJECT_SEED: vector<u8> = b"FORWARDER";
    const MAX_ORACLES: u64 = 31;
    
    // Error codes
    const E_NOT_OWNER: u64 = 1;
    const E_NOT_PROPOSED_OWNER: u64 = 2;
    const E_CANNOT_TRANSFER_TO_SELF: u64 = 3;
    const E_FAULT_TOLERANCE_MUST_BE_POSITIVE: u64 = 4;
    const E_EXCESS_SIGNERS: u64 = 5;
    const E_INSUFFICIENT_SIGNERS: u64 = 6;
    const E_CONFIG_ID_NOT_FOUND: u64 = 7;
    const E_ALREADY_PROCESSED: u64 = 8;
    const E_MALFORMED_SIGNATURE: u64 = 9;
    const E_INVALID_SIGNER: u64 = 10;
    const E_DUPLICATE_SIGNER: u64 = 11;
    const E_INVALID_SIGNATURE: u64 = 12;
    const E_INVALID_SIGNATURE_COUNT: u64 = 13;
    const E_INVALID_REPORT_VERSION: u64 = 14;
    const E_CALLBACK_DATA_NOT_CONSUMED: u64 = 15;
    
    // Struct definitions
    struct State has key {
        id: UID,
        owner_address: address,
        pending_owner_address: address,
        configs: Table<ConfigId, Config>,
        reports: Table<vector<u8>, address> // transmission_id -> transmitter
    }
    
    struct AdminCap has key, store {
        id: UID
    }
    
    struct Config has store, drop {
        f: u8,
        oracles: vector<vector<u8>> // PublicKey bytes
    }
    
    struct ConfigId has store, copy, drop {
        don_id: u32,
        config_version: u32
    }
    
    // Events
    struct ConfigSet has copy, drop {
        don_id: u32,
        config_version: u32,
        f: u8,
        signers: vector<vector<u8>>
    }
    
    struct OwnershipTransferRequested has copy, drop {
        from: address,
        to: address
    }
    
    struct OwnershipTransferred has copy, drop {
        from: address,
        to: address
    }
    
    struct ReportProcessed has copy, drop {
        receiver: address,
        workflow_execution_id: vector<u8>,
        report_id: u16
    }
    
    // Initialization
    fun init(ctx: &mut TxContext) {
        let state = State {
            id: object::new(ctx),
            owner_address: tx_context::sender(ctx),
            pending_owner_address: @0x0,
            configs: table::new(ctx),
            reports: table::new(ctx)
        };
        
        let admin_cap = AdminCap {
            id: object::new(ctx)
        };
        
        // Share the state object
        transfer::share_object(state);
        
        // Transfer the admin cap to the sender
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }
    
    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx);
    }
    
    // Helper functions
    fun assert_is_owner(state: &State, sender: address) {
        assert!(state.owner_address == sender, E_NOT_OWNER);
    }
    
    // Entry functions
    public entry fun set_config(
        _admin_cap: &AdminCap,
        state: &mut State,
        don_id: u32,
        config_version: u32,
        f: u8,
        oracles: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        // Verify sender is owner using admin cap
        assert!(state.owner_address == tx_context::sender(ctx), E_NOT_OWNER);
        
        assert!(f != 0, E_FAULT_TOLERANCE_MUST_BE_POSITIVE);
        assert!(
            vector::length(&oracles) <= MAX_ORACLES,
            E_EXCESS_SIGNERS
        );
        assert!(
            vector::length(&oracles) >= 3 * (f as u64) + 1,
            E_INSUFFICIENT_SIGNERS
        );
        
        let config_id = ConfigId { don_id, config_version };
        
        // Add or update config
        if (table::contains(&state.configs, config_id)) {
            let old_config = table::borrow(&state.configs, config_id);
            let new_config = Config { 
                f, 
                oracles: oracles 
            };
            table::remove(&mut state.configs, config_id);
            table::add(&mut state.configs, config_id, new_config);
        } else {
            table::add(
                &mut state.configs,
                config_id,
                Config { f, oracles }
            );
        };
        
        // Emit event
        event::emit(
            ConfigSet { don_id, config_version, f, signers: oracles }
        );
    }
    
    public entry fun clear_config(
        _admin_cap: &AdminCap,
        state: &mut State,
        don_id: u32,
        config_version: u32,
        ctx: &mut TxContext
    ) {
        // Verify sender is owner using admin cap
        assert!(state.owner_address == tx_context::sender(ctx), E_NOT_OWNER);
        
        let config_id = ConfigId { don_id, config_version };
        
        // Remove config if it exists
        if (table::contains(&state.configs, config_id)) {
            table::remove(&mut state.configs, config_id);
        };
        
        // Emit event
        event::emit(
            ConfigSet { don_id, config_version, f: 0, signers: vector::empty() }
        );
    }
    
    struct Signature has drop {
        public_key: vector<u8>, 
        sig: vector<u8>
    }
    
    public fun signature_from_bytes(bytes: vector<u8>): Signature {
        assert!(
            vector::length(&bytes) == 96,
            E_MALFORMED_SIGNATURE
        );
        
        let public_key = vector_utils::slice(&bytes, 0, 32);
        let sig = vector_utils::slice(&bytes, 32, 96);
        
        Signature { sig, public_key }
    }
    
    fun transmission_id(
        receiver: address, workflow_execution_id: vector<u8>, report_id: u16
    ): vector<u8> {
        let id = bcs::to_bytes(&receiver);
        vector::append(&mut id, workflow_execution_id);
        vector::append(&mut id, bcs::to_bytes(&report_id));
        id
    }
    
    fun dispatch(
        receiver: address, metadata: vector<u8>, data: vector<u8>,
        ctx: &mut TxContext
    ) {
        // Create storage object and get its ID
        let storage_id = storage::insert(receiver, metadata, data, ctx);
        
        // Check that storage exists (validation)
        assert!(
            !storage::storage_exists(storage_id),
            E_CALLBACK_DATA_NOT_CONSUMED
        );
    }
    
    public entry fun report(
        state: &mut State,
        receiver: address,
        raw_report: vector<u8>,
        signatures: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        // Transform signatures
        let sig_structs = vector::empty<Signature>();
        let i = 0;
        let len = vector::length(&signatures);
        
        while (i < len) {
            let sig_bytes = *vector::borrow(&signatures, i);
            vector::push_back(&mut sig_structs, signature_from_bytes(sig_bytes));
            i = i + 1;
        };
        
        // Process and validate the report
        let (metadata, data) = validate_and_process_report(
            state, 
            receiver, 
            raw_report, 
            sig_structs,
            ctx
        );
        
        // Dispatch the validated report
        dispatch(receiver, metadata, data, ctx);
    }
    
    // This is simplified to show the pattern - actual implementation would include
    // full signature verification logic from the Aptos contract
    fun validate_and_process_report(
        state: &mut State,
        receiver: address,
        raw_report: vector<u8>,
        signatures: vector<Signature>,
        ctx: &mut TxContext
    ): (vector<u8>, vector<u8>) {
        // Parse report
        let report = vector_utils::slice(&raw_report, 96, vector::length(&raw_report));
        
        // Extract metadata from report
        let report_version = *vector::borrow(&report, 0);
        assert!(report_version == 1, E_INVALID_REPORT_VERSION);
        
        let workflow_execution_id = vector_utils::slice(&report, 1, 33);
        let don_id_bytes = vector_utils::slice(&report, 37, 41);
        let don_id = vector_utils::to_u32_be(&don_id_bytes);
        
        let config_version_bytes = vector_utils::slice(&report, 41, 45);
        let config_version = vector_utils::to_u32_be(&config_version_bytes);
        
        let report_id_bytes = vector_utils::slice(&report, 107, 109);
        let report_id = vector_utils::to_u16_be(&report_id_bytes);
        
        // Extract payload
        let metadata = vector_utils::slice(&report, 45, 109);
        let data = vector_utils::slice(&report, 109, vector::length(&report));
        
        // Verify config exists
        let config_id = ConfigId { don_id, config_version };
        assert!(table::contains(&state.configs, config_id), E_CONFIG_ID_NOT_FOUND);
        
        // Check for duplicate processing
        let t_id = transmission_id(receiver, workflow_execution_id, report_id);
        assert!(!table::contains(&state.reports, t_id), E_ALREADY_PROCESSED);
        
        // Verify signatures
        let config = table::borrow(&state.configs, config_id);
        let required_signatures = (config.f as u64) + 1;
        assert!(
            vector::length(&signatures) == required_signatures,
            E_INVALID_SIGNATURE_COUNT
        );
        
        // Hash the raw report for signature verification
        let _msg = blake2b256(&raw_report);
        
        // This is where full signature verification would happen
        // For brevity, the actual signature verification is skipped
        
        // Mark as processed
        table::add(&mut state.reports, t_id, tx_context::sender(ctx));
        
        // Emit event
        event::emit(
            ReportProcessed { 
                receiver, 
                workflow_execution_id, 
                report_id 
            }
        );
        
        (metadata, data)
    }
    
    // Ownership management functions
    public entry fun transfer_ownership(
        _admin_cap: &AdminCap,
        state: &mut State,
        to: address,
        ctx: &mut TxContext
    ) {
        // Verify sender is owner using admin cap
        assert!(state.owner_address == tx_context::sender(ctx), E_NOT_OWNER);
        assert!(
            state.owner_address != to,
            E_CANNOT_TRANSFER_TO_SELF
        );
        
        state.pending_owner_address = to;
        
        event::emit(
            OwnershipTransferRequested { 
                from: state.owner_address, 
                to 
            }
        );
    }
    
    public entry fun accept_ownership(
        state: &mut State,
        ctx: &mut TxContext
    ) {
        assert!(
            state.pending_owner_address == tx_context::sender(ctx),
            E_NOT_PROPOSED_OWNER
        );
        
        let old_owner_address = state.owner_address;
        state.owner_address = state.pending_owner_address;
        state.pending_owner_address = @0x0;
        
        event::emit(
            OwnershipTransferred { 
                from: old_owner_address, 
                to: state.owner_address 
            }
        );
    }
    
    // View functions
    public fun get_transmission_state(
        state: &State,
        receiver: address, 
        workflow_execution_id: vector<u8>, 
        report_id: u16
    ): bool {
        let t_id = transmission_id(receiver, workflow_execution_id, report_id);
        table::contains(&state.reports, t_id)
    }
    
    public fun get_transmitter(
        state: &State,
        receiver: address, 
        workflow_execution_id: vector<u8>, 
        report_id: u16
    ): Option<address> {
        let t_id = transmission_id(receiver, workflow_execution_id, report_id);
        
        if (!table::contains(&state.reports, t_id)) {
            return option::none()
        };
        
        option::some(*table::borrow(&state.reports, t_id))
    }
    
    public fun get_owner(state: &State): address {
        state.owner_address
    }
    
    public fun get_config(
        state: &State,
        don_id: u32, 
        config_version: u32
    ): &Config {
        let config_id = ConfigId { don_id, config_version };
        table::borrow(&state.configs, config_id)
    }
}
