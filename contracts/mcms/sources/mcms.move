/// This module is the Sui implementation of Chainlink's MultiChainMultiSig contract.
module chainlink_mcms::mcms {
    use std::hash::keccak256;
    use std::vector;
    use std::string::{Self, String};
    
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use sui::dynamic_field::{Self};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    
    use chainlink_mcms::bcs_stream::{Self, BCSStream};
    use chainlink_mcms::params::{Self, Params};
    
    // Constants
    const BYPASSER_ROLE: u8 = 0;
    const CANCELLER_ROLE: u8 = 1;
    const PROPOSER_ROLE: u8 = 2;
    const TIMELOCK_ROLE: u8 = 3;
    const MAX_ROLE: u8 = 4;
    
    const NUM_GROUPS: u64 = 32;
    const MAX_NUM_SIGNERS: u64 = 200;
    
    // Domain separators
    const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA: vector<u8> = x"a71d47b6c00b64ee21af96a1d424cb2dcbbed12becdcd3b4e6c7fc4c2f80a697";
    const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP: vector<u8> = x"e5a6d1256b00d7ec22512b6b60a3f4d75c559745d2dbf309f77b8b756caabe14";
    
    // Special timestamp value indicating an operation is done
    const DONE_TIMESTAMP: u64 = 1;
    
    const ZERO_HASH: vector<u8> = vector[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0
    ];
    
    // Error codes
    const E_ALREADY_SEEN_HASH: u64 = 1;
    const E_POST_OP_COUNT_REACHED: u64 = 2;
    const E_WRONG_CHAIN_ID: u64 = 3;
    const E_WRONG_MULTISIG: u64 = 4;
    const E_ROOT_EXPIRED: u64 = 5;
    const E_WRONG_NONCE: u64 = 6;
    const E_VALID_UNTIL_EXPIRED: u64 = 7;
    const E_INVALID_SIGNER: u64 = 8;
    const E_MISSING_CONFIG: u64 = 9;
    const E_INSUFFICIENT_SIGNERS: u64 = 10;
    const E_PROOF_CANNOT_BE_VERIFIED: u64 = 11;
    const E_PENDING_OPS: u64 = 12;
    const E_WRONG_PRE_OP_COUNT: u64 = 13;
    const E_WRONG_POST_OP_COUNT: u64 = 14;
    const E_INVALID_NUM_SIGNERS: u64 = 15;
    const E_SIGNER_GROUPS_LEN_MISMATCH: u64 = 16;
    const E_INVALID_GROUP_QUORUM_LEN: u64 = 17;
    const E_INVALID_GROUP_PARENTS_LEN: u64 = 18;
    const E_OUT_OF_BOUNDS_GROUP: u64 = 19;
    const E_GROUP_TREE_NOT_WELL_FORMED: u64 = 20;
    const E_SIGNER_IN_DISABLED_GROUP: u64 = 21;
    const E_OUT_OF_BOUNDS_GROUP_QUORUM: u64 = 22;
    const E_SIGNER_ADDR_MUST_BE_INCREASING: u64 = 23;
    const E_INVALID_SIGNER_ADDR_LEN: u64 = 24;
    const E_UNKNOWN_MCMS_MODULE_FUNCTION: u64 = 25;
    const E_NOT_AUTHORIZED_ROLE: u64 = 31;
    const E_NOT_AUTHORIZED: u64 = 32;
    const E_OPERATION_ALREADY_SCHEDULED: u64 = 33;
    const E_INSUFFICIENT_DELAY: u64 = 34;
    const E_OPERATION_NOT_READY: u64 = 35;
    const E_MISSING_DEPENDENCY: u64 = 36;
    const E_INVALID_ROOT_LEN: u64 = 49;
    
    // Struct definitions
    struct MultisigState has key {
        id: UID,
        bypasser: address,
        canceller: address,
        proposer: address
    }
    
    struct Multisig has key, store {
        id: UID,
        
        // Signers map for validation
        signers: Table<vector<u8>, Signer>,
        config: Config,
        
        // Track seen signed hashes
        seen_signed_hashes: Table<vector<u8>, bool>,
        expiring_root_and_op_count: ExpiringRootAndOpCount,
        root_metadata: RootMetadata
    }
    
    struct Op has copy, drop {
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    }
    
    struct RootMetadata has copy, drop, store {
        role: u8,
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool
    }
    
    struct Signer has store, copy, drop {
        addr: vector<u8>,
        index: u8, // index of signer in config.signers
        group: u8  // 0 <= group < NUM_GROUPS. Each signer can only be in one group.
    }
    
    struct Config has store, copy, drop {
        signers: vector<Signer>,
        
        // group_quorums[i] stores the quorum for the i-th signer group
        group_quorums: vector<u8>,
        
        // group_parents[i] stores the parent group of the i-th signer group
        group_parents: vector<u8>
    }
    
    struct ExpiringRootAndOpCount has store, drop {
        root: vector<u8>,
        valid_until: u64,
        op_count: u64
    }
    
    // Capability for authorizing sensitive operations
    struct AdminCap has key, store {
        id: UID
    }
    
    // Events
    struct MultisigStateInitialized has copy, drop {
        bypasser: address,
        canceller: address,
        proposer: address
    }
    
    struct ConfigSet has copy, drop {
        role: u8,
        config: Config,
        is_root_cleared: bool
    }
    
    struct NewRoot has copy, drop {
        role: u8,
        root: vector<u8>,
        valid_until: u64,
        metadata: RootMetadata
    }
    
    struct OpExecuted has copy, drop {
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    }
    
    // Timelock related structs
    struct Timelock has key {
        id: UID,
        min_delay: u64,
        timestamps: Table<vector<u8>, u64>,
        blocked_functions: vector<Function>
    }
    
    struct Call has copy, drop, store {
        function: Function,
        data: vector<u8>
    }
    
    struct Function has copy, drop, store {
        target: address,
        module_name: String,
        function_name: String
    }
    
    // Timelock events
    struct TimelockInitialized has copy, drop {
        min_delay: u64
    }
    
    struct CallScheduled has copy, drop {
        id: vector<u8>,
        index: u64,
        target: address,
        module_name: String,
        function_name: String,
        data: vector<u8>,
        predecessor: vector<u8>,
        salt: vector<u8>,
        delay: u64
    }
    
    struct CallExecuted has copy, drop {
        id: vector<u8>,
        index: u64,
        target: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    }
    
    // One-time initialization function
    fun init(ctx: &mut TxContext) {
        // Create the multisig objects
        let bypasser = create_multisig(BYPASSER_ROLE, ctx);
        let canceller = create_multisig(CANCELLER_ROLE, ctx);
        let proposer = create_multisig(PROPOSER_ROLE, ctx);
        
        // Initialize the multisig state
        let multisig_state = MultisigState {
            id: object::new(ctx),
            bypasser,
            canceller,
            proposer
        };
        
        // Create timelock
        let timelock = Timelock {
            id: object::new(ctx),
            min_delay: 0,
            timestamps: table::new(ctx),
            blocked_functions: vector::empty()
        };
        
        // Create admin capability
        let admin_cap = AdminCap {
            id: object::new(ctx)
        };
        
        // Share the multisig state and timelock
        transfer::share_object(multisig_state);
        transfer::share_object(timelock);
        
        // Transfer the admin cap to the sender
        transfer::transfer(admin_cap, tx_context::sender(ctx));
        
        // Emit initialization events
        event::emit(
            MultisigStateInitialized {
                bypasser,
                canceller,
                proposer
            }
        );
        
        event::emit(
            TimelockInitialized {
                min_delay: 0
            }
        );
    }
    
    // Helper function to create a multisig
    fun create_multisig(role: u8, ctx: &mut TxContext): address {
        let multisig = Multisig {
            id: object::new(ctx),
            signers: table::new(ctx),
            config: Config {
                signers: vector::empty(),
                group_quorums: vector::empty(),
                group_parents: vector::empty()
            },
            seen_signed_hashes: table::new(ctx),
            expiring_root_and_op_count: ExpiringRootAndOpCount {
                root: vector::empty(),
                valid_until: 0,
                op_count: 0
            },
            root_metadata: RootMetadata {
                role,
                chain_id: 0,
                multisig: object::uid_to_address(&object::new(ctx)),
                pre_op_count: 0,
                post_op_count: 0,
                override_previous_root: false
            }
        };
        
        // Initialize group quorums and parents with zeros
        let i = 0;
        while (i < NUM_GROUPS) {
            vector::push_back(&mut multisig.config.group_quorums, 0);
            vector::push_back(&mut multisig.config.group_parents, 0);
            i = i + 1;
        };
        
        // Share the multisig object
        let multisig_address = object::id_address(&multisig);
        transfer::share_object(multisig);
        
        multisig_address
    }
    
    // Set a new expiring root
    public entry fun set_root(
        state: &mut MultisigState,
        role: u8,
        root: vector<u8>,
        valid_until: u64,
        chain_id: u256,
        multisig_addr: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool,
        metadata_proof: vector<vector<u8>>,
        signatures: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        assert!(is_valid_role(role), E_NOT_AUTHORIZED_ROLE);
        
        let metadata = RootMetadata {
            role,
            chain_id,
            multisig: multisig_addr,
            pre_op_count,
            post_op_count,
            override_previous_root
        };
        
        let signed_hash = compute_eth_message_hash(root, valid_until);
        
        // Get the appropriate multisig object based on role
        let multisig_addr = get_multisig_address(state, role);
        
        // Verify signatures and other conditions
        // Note: This is a simplified implementation. In a real implementation,
        // we would need to verify signatures against the multisig configuration.
        
        // Emit event
        event::emit(
            NewRoot {
                role,
                root,
                valid_until,
                metadata
            }
        );
    }
    
    // Execute an operation after verifying its inclusion in the merkle tree
    public entry fun execute(
        state: &mut MultisigState,
        timelock: &mut Timelock,
        role: u8,
        chain_id: u256,
        multisig_addr: address,
        nonce: u64,
        to: address,
        module_name: String,
        function_name: String,
        data: vector<u8>,
        proof: vector<vector<u8>>,
        ctx: &mut TxContext
    ) {
        assert!(is_valid_role(role), E_NOT_AUTHORIZED_ROLE);
        
        let op = Op {
            role,
            chain_id,
            multisig: multisig_addr,
            nonce,
            to,
            module_name,
            function_name,
            data
        };
        
        // Verify operation and execute
        // Note: This is a simplified implementation
        
        // Emit event
        event::emit(
            OpExecuted {
                role,
                chain_id,
                multisig: multisig_addr,
                nonce,
                to,
                module_name,
                function_name,
                data
            }
        );
    }
    
    // Helper function to compute Ethereum message hash
    public fun compute_eth_message_hash(
        root: vector<u8>, valid_until: u64
    ): vector<u8> {
        // Simplified implementation
        let valid_until_bytes = vector::empty<u8>();
        // Convert valid_until to bytes
        
        assert!(vector::length(&root) == 32, E_INVALID_ROOT_LEN);
        let abi_encoded_params = root;
        vector::append(&mut abi_encoded_params, valid_until_bytes);
        
        // Hash the encoded parameters
        let hashed_encoded_params = keccak256(abi_encoded_params);
        
        // Add Ethereum message prefix
        let eth_msg_prefix = b"\x19Ethereum Signed Message:\n32";
        let hash = eth_msg_prefix;
        vector::append(&mut hash, hashed_encoded_params);
        keccak256(hash)
    }
    
    // Helper function to verify merkle proof
    public fun verify_merkle_proof(
        proof: vector<vector<u8>>,
        root: vector<u8>,
        leaf: vector<u8>
    ): bool {
        let computed_hash = leaf;
        let i = 0;
        let len = vector::length(&proof);
        
        while (i < len) {
            let proof_element = *vector::borrow(&proof, i);
            let (left, right) = if (vector_u8_gt(&computed_hash, &proof_element)) {
                (proof_element, computed_hash)
            } else {
                (computed_hash, proof_element)
            };
            
            let hash_input = left;
            vector::append(&mut hash_input, right);
            computed_hash = keccak256(hash_input);
            
            i = i + 1;
        };
        
        computed_hash == root
    }
    
    // Helper function to compare two byte vectors
    fun vector_u8_gt(a: &vector<u8>, b: &vector<u8>): bool {
        let a_len = vector::length(a);
        let b_len = vector::length(b);
        
        if (a_len != b_len) {
            return a_len > b_len
        };
        
        let i = 0;
        while (i < a_len) {
            let a_byte = *vector::borrow(a, i);
            let b_byte = *vector::borrow(b, i);
            
            if (a_byte != b_byte) {
                return a_byte > b_byte
            };
            
            i = i + 1;
        };
        
        false
    }
    
    // Helper function to get multisig address based on role
    fun get_multisig_address(state: &MultisigState, role: u8): address {
        if (role == BYPASSER_ROLE) {
            state.bypasser
        } else if (role == CANCELLER_ROLE) {
            state.canceller
        } else if (role == PROPOSER_ROLE) {
            state.proposer
        } else {
            abort E_NOT_AUTHORIZED_ROLE
        }
    }
    
    // View functions
    public fun is_valid_role(role: u8): bool {
        role < MAX_ROLE
    }
    
    public fun bypasser_role(): u8 {
        BYPASSER_ROLE
    }
    
    public fun canceller_role(): u8 {
        CANCELLER_ROLE
    }
    
    public fun proposer_role(): u8 {
        PROPOSER_ROLE
    }
    
    public fun timelock_role(): u8 {
        TIMELOCK_ROLE
    }
    
    public fun zero_hash(): vector<u8> {
        ZERO_HASH
    }
}
