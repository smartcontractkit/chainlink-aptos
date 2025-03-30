/// This module is the Aptos implementation of Chainlink's MultiChainMultiSig contract.
module mcms::mcms {
    use std::aptos_hash::keccak256;
    use std::bcs;
    use std::event;
    use std::option::{Self, Option};
    use std::signer;
    use std::simple_map::{Self, SimpleMap};
    use std::string::{Self, String};
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_std::smart_vector::{Self, SmartVector};
    use aptos_framework::chain_id;
    use aptos_framework::object::{Self, ExtendRef, Object};
    use aptos_framework::timestamp;

    use mcms::bcs_stream;
    use mcms::mcms_account;
    use mcms::mcms_deployer;
    use mcms::mcms_registry;
    use mcms::merkle;
    use mcms::params::{Self, Call, Function};

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
    const E_UNKNOWN_FRAMEWORK_MODULE_FUNCTION: u64 = 26;
    const E_UNKNOWN_FRAMEWORK_MODULE: u64 = 27;
    const E_SELF_CALL_ROLE_MISMATCH: u64 = 28;
    const E_NOT_BYPASSER_ROLE: u64 = 29;
    const E_INVALID_ROLE: u64 = 30;
    const E_NOT_AUTHORIZED_ROLE: u64 = 31;
    const E_NOT_AUTHORIZED: u64 = 32;
    const E_OPERATION_ALREADY_SCHEDULED: u64 = 33;
    const E_INSUFFICIENT_DELAY: u64 = 34;
    const E_OPERATION_NOT_READY: u64 = 35;
    const E_MISSING_DEPENDENCY: u64 = 36;
    const E_OPERATION_CANNOT_BE_CANCELLED: u64 = 37;
    const E_FUNCTION_BLOCKED: u64 = 38;
    const E_INVALID_INDEX: u64 = 39;
    const E_UNKNOWN_MCMS_ACCOUNT_MODULE_FUNCTION: u64 = 40;
    const E_UNKNOWN_MCMS_DEPLOYER_MODULE_FUNCTION: u64 = 41;
    const E_UNKNOWN_MCMS_REGISTRY_MODULE_FUNCTION: u64 = 42;

    const BYPASSER_ROLE: u8 = 0;
    const CANCELLER_ROLE: u8 = 1;
    const PROPOSER_ROLE: u8 = 2;
    const MAX_ROLE: u8 = 3;

    const NUM_GROUPS: u64 = 32;
    const MAX_NUM_SIGNERS: u64 = 200;
    // equivalent to initializing empty uint8[NUM_GROUPS] in Solidity
    const VEC_NUM_GROUPS: vector<u8> = vector[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0
    ];
    // keccak256("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA_APTOS")
    const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA: vector<u8> = x"a71d47b6c00b64ee21af96a1d424cb2dcbbed12becdcd3b4e6c7fc4c2f80a697";
    // keccak256("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP_APTOS")
    const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP: vector<u8> = x"e5a6d1256b00d7ec22512b6b60a3f4d75c559745d2dbf309f77b8b756caabe14";

    /// Special timestamp value indicating an operation is done
    const DONE_TIMESTAMP: u64 = 1;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct MultisigState has key {
        bypasser: Object<Multisig>,
        canceller: Object<Multisig>,
        proposer: Object<Multisig>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Timelock has key {
        min_delay: u64,
        /// hashed batch of hashed calls -> timestamp
        timestamps: SmartTable<vector<u8>, u64>,
        /// blocked functions
        blocked_functions: SmartVector<Function>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Multisig has key {
        extend_ref: ExtendRef,

        /// signers is used to easily validate the existence of the signer by its address. We still
        /// have signers stored in config in order to easily deactivate them when a new config is set.
        signers: SimpleMap<vector<u8>, Signer>,
        config: Config,

        /// Remember signedHashes that this contract has seen. Each signedHash can only be set once.
        seen_signed_hashes: SimpleMap<vector<u8>, bool>,
        expiring_root_and_op_count: ExpiringRootAndOpCount,
        root_metadata: RootMetadata
    }

    struct RootMetadata has copy, drop, store {
        role: u8,
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool
    }

    struct Op has copy, drop {
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function: String,
        data: vector<u8>
    }

    struct Signer has store, copy, drop {
        addr: vector<u8>,
        index: u8, // index of signer in config.signers
        group: u8 // 0 <= group < NUM_GROUPS. Each signer can only be in one group.
    }

    struct Config has store, copy, drop {
        signers: vector<Signer>,

        // group_quorums[i] stores the quorum for the i-th signer group. Any group with
        // group_quorums[i] = 0 is considered disabled. The i-th group is successful if
        // it is enabled and at least group_quorums[i] of its children are successful.
        group_quorums: vector<u8>,

        // group_parents[i] stores the parent group of the i-th signer group. We ensure that the
        // groups form a tree structure (where the root/0-th signer group points to itself as
        // parent) by enforcing
        // - (i != 0) implies (group_parents[i] < i)
        // - group_parents[0] == 0
        group_parents: vector<u8>
    }

    struct ExpiringRootAndOpCount has store, drop {
        root: vector<u8>,
        valid_until: u64,
        op_count: u64
    }

    #[event]
    struct MultisigStateInitialized has drop, store {
        bypasser: Object<Multisig>,
        canceller: Object<Multisig>,
        proposer: Object<Multisig>
    }

    #[event]
    struct TimelockInitialized has drop, store {
        min_delay: u64
    }

    #[event]
    struct ConfigSet has drop, store {
        role: u8,
        config: Config,
        is_root_cleared: bool
    }

    #[event]
    struct NewRoot has drop, store {
        role: u8,
        root: vector<u8>,
        valid_until: u64,
        metadata: RootMetadata
    }

    #[event]
    struct OpExecuted has drop, store {
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function: String,
        data: vector<u8>
    }

    #[event]
    struct CallScheduled has drop, store {
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

    #[event]
    struct CallExecuted has drop, store {
        id: vector<u8>,
        index: u64,
        target: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    }

    #[event]
    struct BypasserCallExecuted has drop, store {
        index: u64,
        target: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    }

    #[event]
    struct Cancelled has drop, store {
        id: vector<u8>
    }

    #[event]
    struct MinDelayChange has drop, store {
        old_min_delay: u64,
        new_min_delay: u64
    }

    #[event]
    struct FunctionBlocked has drop, store {
        target: address,
        module_name: String,
        function_name: String
    }

    #[event]
    struct FunctionUnblocked has drop, store {
        target: address,
        module_name: String,
        function_name: String
    }

    #[event]
    struct RoleGranted has drop, store {
        role: u8,
        account: address,
        granter: address
    }

    #[event]
    struct RoleRevoked has drop, store {
        role: u8,
        account: address,
        granter: address
    }

    fun init_module(deployer: &signer) {
        let bypasser = create_multisig(deployer, BYPASSER_ROLE);
        let canceller = create_multisig(deployer, CANCELLER_ROLE);
        let proposer = create_multisig(deployer, PROPOSER_ROLE);

        move_to(
            deployer,
            MultisigState { bypasser, canceller, proposer }
        );

        event::emit(MultisigStateInitialized { bypasser, canceller, proposer });

        move_to(
            deployer,
            Timelock {
                min_delay: 0,
                timestamps: smart_table::new(),
                blocked_functions: smart_vector::new()
            }
        );

        event::emit(TimelockInitialized { min_delay: 0 });
    }

    inline fun create_multisig(deployer: &signer, role: u8): Object<Multisig> {
        let constructor_ref = &object::create_object(signer::address_of(deployer));
        let object_signer = object::generate_signer(constructor_ref);
        let extend_ref = object::generate_extend_ref(constructor_ref);

        move_to(
            &object_signer,
            Multisig {
                extend_ref,
                signers: simple_map::new(),
                config: Config {
                    signers: vector[],
                    group_quorums: VEC_NUM_GROUPS,
                    group_parents: VEC_NUM_GROUPS
                },
                seen_signed_hashes: simple_map::new(),
                expiring_root_and_op_count: ExpiringRootAndOpCount {
                    root: vector[],
                    valid_until: 0,
                    op_count: 0
                },
                root_metadata: RootMetadata {
                    role,
                    chain_id: 0,
                    multisig: signer::address_of(&object_signer),
                    pre_op_count: 0,
                    post_op_count: 0,
                    override_previous_root: false
                }
            }
        );

        object::object_from_constructor_ref(constructor_ref)
    }

    fun multisig_signer(multisig: Object<Multisig>): signer acquires Multisig {
        let multisig_mut = borrow_multisig(multisig);
        object::generate_signer_for_extending(&multisig_mut.extend_ref)
    }

    /// @notice set_root Sets a new expiring root.
    ///
    /// @param root is the new expiring root.
    /// @param valid_until is the time by which root is valid
    /// @param chain_id is the chain id of the chain on which the root is valid
    /// @param multisig is the address of the multisig to set the root for
    /// @param pre_op_count is the number of operations that have been executed before this root was set
    /// @param post_op_count is the number of operations that have been executed after this root was set
    /// @param override_previous_root is a boolean that indicates whether to override the previous root
    /// @param metadata_proof is the MerkleProof of inclusion of the metadata in the Merkle tree.
    /// @param signatures the ECDSA signatures on (root, valid_until).
    ///
    /// @dev the message (root, valid_until) should be signed by a sufficient set of signers.
    /// This signature authenticates also the metadata.
    ///
    /// @dev this method can be executed by anyone who has the root and valid signatures.
    /// as we validate the correctness of signatures, this imposes no risk.
    public entry fun set_root(
        _caller: &signer,
        role: u8,
        root: vector<u8>,
        valid_until: u64,
        chain_id: u256,
        multisig_addr: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool,
        metadata_proof: vector<vector<u8>>,
        signatures: vector<vector<u8>>
    ) acquires Multisig, MultisigState {
        assert!(is_valid_role(role), E_INVALID_ROLE);

        let metadata = RootMetadata {
            role,
            chain_id,
            multisig: multisig_addr,
            pre_op_count,
            post_op_count,
            override_previous_root
        };

        let signed_hash = merkle::compute_eth_message_hash(root, valid_until);

        // Validate that `multisig` is a registered multisig for `role`.
        let multisig = borrow_multisig_mut(multisig_object(role));

        assert!(
            !multisig.seen_signed_hashes.contains_key(&signed_hash),
            E_ALREADY_SEEN_HASH
        );
        assert!(timestamp::now_seconds() <= valid_until, E_VALID_UNTIL_EXPIRED);
        assert!(metadata.chain_id == (chain_id::get() as u256), E_WRONG_CHAIN_ID);
        assert!(metadata.multisig == @mcms, E_WRONG_MULTISIG);

        let op_count = multisig.expiring_root_and_op_count.op_count;
        assert!(
            override_previous_root || op_count == multisig.root_metadata.post_op_count,
            E_PENDING_OPS
        );

        assert!(op_count == metadata.pre_op_count, E_WRONG_PRE_OP_COUNT);
        assert!(metadata.pre_op_count <= metadata.post_op_count, E_WRONG_POST_OP_COUNT);

        let metadata_leaf_hash = hash_metadata_leaf(metadata);
        assert!(
            merkle::verify_merkle_proof(metadata_proof, root, metadata_leaf_hash),
            E_PROOF_CANNOT_BE_VERIFIED
        );

        let prev_address = vector[];
        let group_vote_counts: vector<u8> = vector[];
        params::right_pad_vec(&mut group_vote_counts, NUM_GROUPS);

        let signatures_len = signatures.length();
        for (i in 0..signatures_len) {
            let signature = signatures[i];
            let signer_addr = merkle::ecdsa_recover_evm_addr(signed_hash, signature);
            // the off-chain system is required to sort the signatures by the
            // signer address in an increasing order
            if (i > 0) {
                assert!(
                    params::vector_u8_gt(&signer_addr, &prev_address),
                    E_SIGNER_ADDR_MUST_BE_INCREASING
                );
            };
            prev_address = signer_addr;

            assert!(multisig.signers.contains_key(&signer_addr), E_INVALID_SIGNER);
            let signer = *multisig.signers.borrow(&signer_addr);

            // check group quorums
            let group: u8 = signer.group;
            while (true) {
                let group_vote_count = group_vote_counts.borrow_mut((group as u64));
                *group_vote_count += 1;

                let quorum = multisig.config.group_quorums.borrow((group as u64));
                if (*group_vote_count != *quorum) {
                    // bail out unless we just hit the quorum. we only hit each quorum once,
                    // so we never move on to the parent of a group more than once.
                    break
                };

                if (group == 0) {
                    // root group reached
                    break
                };

                // group quorum reached, restart loop and check parent group
                group = multisig.config.group_parents[(group as u64)];
            };
        };

        // the group at the root of the tree (with index 0) determines whether the vote passed,
        // we cannot proceed if it isn't configured with a valid (non-zero) quorum
        let root_group_quorum = multisig.config.group_quorums[0];
        assert!(root_group_quorum != 0, E_MISSING_CONFIG);

        // check root group reached quorum
        let root_group_vote_count = group_vote_counts[0];
        assert!(root_group_vote_count >= root_group_quorum, E_INSUFFICIENT_SIGNERS);

        multisig.seen_signed_hashes.add(signed_hash, true);
        multisig.expiring_root_and_op_count = ExpiringRootAndOpCount {
            root,
            valid_until,
            op_count: metadata.pre_op_count
        };
        multisig.root_metadata = metadata;

        event::emit(
            NewRoot {
                role,
                root,
                valid_until,
                metadata: RootMetadata {
                    role,
                    chain_id,
                    multisig: multisig_addr,
                    pre_op_count: metadata.pre_op_count,
                    post_op_count: metadata.post_op_count,
                    override_previous_root: metadata.override_previous_root
                }
            }
        );
    }

    /// Execute an operation after verifying its inclusion in the merkle tree
    public entry fun execute(
        _caller: &signer,
        role: u8,
        chain_id: u256,
        multisig_addr: address,
        nonce: u64,
        to: address,
        module_name: String,
        function: String,
        data: vector<u8>,
        proof: vector<vector<u8>>
    ) acquires Multisig, MultisigState, Timelock {
        assert!(is_valid_role(role), E_INVALID_ROLE);

        let op =
            merkle::create_op(
                role,
                chain_id,
                multisig_addr,
                nonce,
                to,
                module_name,
                function,
                data
            );

        let multisig = borrow_multisig_mut(multisig_object(role));

        assert!(
            multisig.root_metadata.post_op_count
                > multisig.expiring_root_and_op_count.op_count,
            E_POST_OP_COUNT_REACHED
        );
        assert!(chain_id == (chain_id::get() as u256), E_WRONG_CHAIN_ID);
        assert!(
            timestamp::now_seconds() <= multisig.expiring_root_and_op_count.valid_until,
            E_ROOT_EXPIRED
        );
        assert!(merkle::multisig(op) == @mcms, E_WRONG_MULTISIG);
        assert!(nonce == multisig.expiring_root_and_op_count.op_count, E_WRONG_NONCE);

        // computes keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP, op))
        let hashed_leaf: vector<u8> =
            merkle::hash_op_leaf(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP, op);
        assert!(
            merkle::verify_merkle_proof(
                proof, multisig.expiring_root_and_op_count.root, hashed_leaf
            ),
            E_PROOF_CANNOT_BE_VERIFIED
        );

        multisig.expiring_root_and_op_count.op_count += 1;

        dispatch_with_role(role, to, module_name, function, data);

        event::emit(
            OpExecuted {
                role,
                chain_id,
                multisig: multisig_addr,
                nonce,
                to,
                module_name,
                function,
                data
            }
        );
    }

    /// Calling from `execute`
    /// Signatures and proofs are already validated at this point.
    inline fun dispatch_with_role(
        role: u8,
        to: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    ) {
        let role = option::some(role);
        dispatch(role, to, module_name, function_name, data);
    }

    /// If we reach here, we know that the call was scheduled and is ready to be executed.
    /// No role checks are needed here because the call was already scheduled by a bypasser or proposer.
    inline fun dispatch_without_role(
        target: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    ) {
        let role = option::none();
        dispatch(role, target, module_name, function_name, data);
    }

    inline fun dispatch(
        role: Option<u8>,
        target: address,
        module_name: String,
        function_name: String,
        data: vector<u8>
    ) {
        let module_name_bytes = *module_name.bytes();
        let function_name_bytes = *function_name.bytes();

        if (target == @mcms) {
            if (module_name_bytes == b"mcms") {
                // dispatch to the mcms module's functions for setting config, scheduling, executing, and canceling operations.
                dispatch_to_self(role, function_name_bytes, data);
            } else if (module_name_bytes == b"mcms_account") {
                // dispatch to the account module's functions for ownership transfers.
                dispatch_to_account(role, function_name_bytes, data);
            } else if (module_name_bytes == b"mcms_deployer") {
                // dispatch to the deployer module's functions for deploying and upgrading contracts.
                dispatch_to_deployer(role, function_name_bytes, data);
            } else if (module_name_bytes == b"mcms_registry") {
                // dispatch to the registry module's functions for code object management.
                dispatch_to_registry(role, function_name_bytes, data);
            }
        } else {
            let object_meta =
                mcms_registry::start_dispatch(target, module_name, function_name, data);
            aptos_framework::dispatchable_fungible_asset::derived_supply(object_meta);
            mcms_registry::finish_dispatch(target);
        }
    }

    /// If called from `execute`, we must check that the role is allowed to call this function.
    /// If called from `execute_call`, this is ready to be executed.
    inline fun dispatch_to_self(
        role: Option<u8>, function_name_bytes: vector<u8>, data: vector<u8>
    ) {
        let stream = bcs_stream::new(data);
        if (function_name_bytes == b"set_config") {
            assert_bypasser_role(role);

            let role = bcs_stream::deserialize_u8(&mut stream);
            let signer_addresses =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| { bcs_stream::deserialize_vector_u8(stream) }
                );
            let signer_groups = bcs_stream::deserialize_vector_u8(&mut stream);
            let group_quorums = bcs_stream::deserialize_vector_u8(&mut stream);
            let group_parents = bcs_stream::deserialize_vector_u8(&mut stream);
            let clear_root = bcs_stream::deserialize_bool(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            set_config(
                &mcms_account::get_signer(), // Must get MCMS signer for `set_config`
                role,
                signer_addresses,
                signer_groups,
                group_quorums,
                group_parents,
                clear_root
            );
        } else if (function_name_bytes == b"schedule_batch") {
            assert_bypasser_or_proposer_role(role);

            let (targets, module_names, function_names, datas, predecessor, salt, delay) =
                params::deserialize_schedule_batch_params(data);
            schedule_batch(
                &get_signer(role),
                targets,
                module_names,
                function_names,
                datas,
                predecessor,
                salt,
                delay
            );
        } else if (function_name_bytes == b"bypasser_execute_batch") {
            assert_bypasser_role(role);

            let (targets, module_names, function_names, datas) =
                params::deserialize_bypasser_execute_batch_params(data);
            bypasser_execute_batch(
                &get_signer(role),
                targets,
                module_names,
                function_names,
                datas
            );
        } else if (function_name_bytes == b"execute_batch") {
            let (targets, module_names, function_names, datas, predecessor, salt) =
                params::deserialize_execute_batch_params(data);
            execute_batch(
                &mcms_account::get_signer(), // Anyone can call `execute_batch`
                targets,
                module_names,
                function_names,
                datas,
                predecessor,
                salt
            );
        } else if (function_name_bytes == b"cancel") {
            assert_bypasser_or_canceller_role(role);
            let id = params::deserialize_cancel_params(data);
            cancel(&get_signer(role), id);
        } else if (function_name_bytes == b"update_min_delay") {
            assert_bypasser_role(role);
            let new_min_delay = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            update_min_delay(&get_signer(role), new_min_delay);
        } else {
            abort E_UNKNOWN_MCMS_MODULE_FUNCTION
        }
    }

    /// Schedule a batch of calls to be executed after a delay.
    /// This function can only be called by users with the PROPOSER or BYPASSER role.
    public entry fun schedule_batch(
        caller: &signer,
        targets: vector<address>,
        module_names: vector<String>,
        function_names: vector<String>,
        datas: vector<vector<u8>>,
        predecessor: vector<u8>,
        salt: vector<u8>,
        delay: u64
    ) acquires MultisigState, Timelock {
        let caller_address = signer::address_of(caller);
        let is_bypasser = is_bypasser(caller_address);
        assert!(
            is_proposer(caller_address)
                || is_bypasser
                || mcms_account::is_owner(caller_address),
            E_NOT_AUTHORIZED
        );

        let timelock = borrow_timelock();
        if (!is_bypasser) {
            assert!(delay >= timelock.min_delay, E_INSUFFICIENT_DELAY);
        };

        let calls = params::create_calls(targets, module_names, function_names, datas);
        schedule_batch_internal(caller_address, calls, predecessor, salt, delay);
    }

    fun schedule_batch_internal(
        caller: address,
        calls: vector<Call>,
        predecessor: vector<u8>,
        salt: vector<u8>,
        delay: u64
    ) acquires MultisigState, Timelock {
        for (i in 0..calls.length()) {
            let call = calls[i];
            let function = params::call_function(call);
            assert!(
                !is_function_blocked(
                    params::target(function),
                    params::module_name(function),
                    params::function_name(function)
                ) || is_bypasser(caller),
                E_FUNCTION_BLOCKED
            );
        };

        let id = params::hash_operation_batch(calls, predecessor, salt);
        schedule(id, delay);

        for (i in 0..calls.length()) {
            let call = calls[i];
            let function = params::call_function(call);
            event::emit(
                CallScheduled {
                    id,
                    index: i,
                    target: params::target(function),
                    module_name: params::module_name(function),
                    function_name: params::function_name(function),
                    data: params::data(call),
                    predecessor,
                    salt,
                    delay
                }
            );
        };
    }

    fun schedule(id: vector<u8>, delay: u64) acquires Timelock {
        let timelock = borrow_mut_timelock();
        assert!(!timelock.timestamps.contains(id), E_OPERATION_ALREADY_SCHEDULED);

        let timestamp = timestamp::now_seconds() + timelock.min_delay + delay;
        timelock.timestamps.add(id, timestamp);
    }

    /// Anyone can call this as it checks if the operation was scheduled by a bypasser or proposer.
    public entry fun execute_batch(
        _caller: &signer,
        targets: vector<address>,
        module_names: vector<String>,
        function_names: vector<String>,
        datas: vector<vector<u8>>,
        predecessor: vector<u8>,
        salt: vector<u8>
    ) acquires Multisig, MultisigState, Timelock {
        let calls = params::create_calls(targets, module_names, function_names, datas);

        for (i in 0..calls.length()) {
            let call = calls[i];
            let function = params::call_function(call);
            assert!(
                !is_function_blocked(
                    params::target(function),
                    params::module_name(function),
                    params::function_name(function)
                ),
                E_FUNCTION_BLOCKED
            );
        };

        let id = params::hash_operation_batch(calls, predecessor, salt);

        before_call(id, predecessor);

        for (i in 0..calls.length()) {
            let call = calls[i];
            let function = params::call_function(call);
            let target = params::target(function);
            let module_name = params::module_name(function);
            let function_name = params::function_name(function);
            let data = params::data(call);

            dispatch_without_role(target, module_name, function_name, data);

            event::emit(
                CallExecuted { id, index: i, target, module_name, function_name, data }
            );
        };

        after_call(id);
    }

    inline fun before_call(id: vector<u8>, predecessor: vector<u8>) acquires Timelock {
        assert!(is_operation_ready(id), E_OPERATION_NOT_READY);
        if (!predecessor.is_empty()) {
            assert!(is_operation_done(predecessor), E_MISSING_DEPENDENCY);
        };
    }

    inline fun after_call(id: vector<u8>) acquires Timelock {
        assert!(is_operation_ready(id), E_OPERATION_NOT_READY);
        *borrow_mut_timelock().timestamps.borrow_mut(id) = DONE_TIMESTAMP;
    }

    inline fun dispatch_to_account(
        role: Option<u8>, function_name_bytes: vector<u8>, data: vector<u8>
    ) {
        assert_bypasser_role(role);

        let stream = bcs_stream::new(data);
        let self_signer = &get_signer(role);
        if (function_name_bytes == b"transfer_ownership") {
            let target = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            mcms_account::transfer_ownership(self_signer, target);
        } else if (function_name_bytes == b"accept_ownership") {
            mcms_account::accept_ownership(self_signer);
        } else {
            abort E_UNKNOWN_MCMS_ACCOUNT_MODULE_FUNCTION;
        }
    }

    inline fun dispatch_to_deployer(
        role: Option<u8>, function_name_bytes: vector<u8>, data: vector<u8>
    ) {
        assert_bypasser_role(role);

        let self_signer = &get_signer(role);
        let stream = bcs_stream::new(data);
        if (function_name_bytes == b"stage_code_chunk") {
            let metadata_chunk = bcs_stream::deserialize_vector_u8(&mut stream);
            let code_indices =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| { bcs_stream::deserialize_u16(stream) }
                );
            let code_chunks =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| { bcs_stream::deserialize_vector_u8(stream) }
                );
            mcms_deployer::stage_code_chunk(
                self_signer,
                metadata_chunk,
                code_indices,
                code_chunks
            );
        } else if (function_name_bytes == b"stage_code_chunk_and_publish_to_object") {
            let metadata_chunk = bcs_stream::deserialize_vector_u8(&mut stream);
            let code_indices =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| { bcs_stream::deserialize_u16(stream) }
                );
            let code_chunks =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| { bcs_stream::deserialize_vector_u8(stream) }
                );
            let new_owner_seed = bcs_stream::deserialize_vector_u8(&mut stream);
            mcms_deployer::stage_code_chunk_and_publish_to_object(
                self_signer,
                metadata_chunk,
                code_indices,
                code_chunks,
                new_owner_seed
            );
        } else if (function_name_bytes == b"stage_code_chunk_and_upgrade_object_code") {
            let metadata_chunk = bcs_stream::deserialize_vector_u8(&mut stream);
            let code_indices =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| { bcs_stream::deserialize_u16(stream) }
                );
            let code_chunks =
                bcs_stream::deserialize_vector(
                    &mut stream,
                    |stream| { bcs_stream::deserialize_vector_u8(stream) }
                );
            let code_object_address = bcs_stream::deserialize_address(&mut stream);
            mcms_deployer::stage_code_chunk_and_upgrade_object_code(
                self_signer,
                metadata_chunk,
                code_indices,
                code_chunks,
                code_object_address
            );
        } else if (function_name_bytes == b"cleanup_staging_area") {
            bcs_stream::assert_is_consumed(&stream);
            mcms_deployer::cleanup_staging_area(self_signer);
        } else {
            abort E_UNKNOWN_MCMS_DEPLOYER_MODULE_FUNCTION;
        }
    }

    inline fun dispatch_to_registry(
        role: Option<u8>, function_name_bytes: vector<u8>, data: vector<u8>
    ) {
        assert_bypasser_role(role);

        let stream = bcs_stream::new(data);
        let self_signer = &mcms_account::get_signer();
        if (function_name_bytes == b"create_owner_for_preexisting_code_object") {
            let object_address = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            mcms_registry::create_owner_for_preexisting_code_object(
                self_signer, object_address
            );
        } else if (function_name_bytes == b"transfer_code_object") {
            let object_address = bcs_stream::deserialize_address(&mut stream);
            let new_owner_address = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            mcms_registry::transfer_code_object(
                self_signer, object_address, new_owner_address
            );
        } else {
            abort E_UNKNOWN_MCMS_REGISTRY_MODULE_FUNCTION;
        }
    }

    fun get_signer(role: Option<u8>): signer acquires Multisig, MultisigState {
        if (role.is_some()) {
            let role_value = *role.borrow();
            multisig_signer(multisig_object(role_value))
        } else {
            mcms_account::get_signer()
        }
    }

    fun assert_bypasser_role(role: Option<u8>) {
        if (role.is_some()) {
            assert!(*role.borrow() == BYPASSER_ROLE, E_NOT_BYPASSER_ROLE);
        };
    }

    fun assert_bypasser_or_proposer_role(role: Option<u8>) {
        if (role.is_some()) {
            assert!(
                *role.borrow() == BYPASSER_ROLE || *role.borrow() == PROPOSER_ROLE,
                E_INVALID_ROLE
            );
        };
    }

    fun assert_bypasser_or_canceller_role(role: Option<u8>) {
        if (role.is_some()) {
            assert!(
                *role.borrow() == BYPASSER_ROLE || *role.borrow() == CANCELLER_ROLE,
                E_INVALID_ROLE
            );
        };
    }

    /// Updates the multisig configuration, including signer addresses and group settings.
    public entry fun set_config(
        caller: &signer,
        role: u8,
        signer_addresses: vector<vector<u8>>,
        signer_groups: vector<u8>,
        group_quorums: vector<u8>,
        group_parents: vector<u8>,
        clear_root: bool
    ) acquires Multisig, MultisigState {
        mcms_account::assert_is_owner(caller);

        assert!(
            signer_addresses.length() != 0
                && signer_addresses.length() <= MAX_NUM_SIGNERS,
            E_INVALID_NUM_SIGNERS
        );
        assert!(
            signer_addresses.length() == signer_groups.length(),
            E_SIGNER_GROUPS_LEN_MISMATCH
        );
        assert!(group_quorums.length() == NUM_GROUPS, E_INVALID_GROUP_QUORUM_LEN);
        assert!(group_parents.length() == NUM_GROUPS, E_INVALID_GROUP_PARENTS_LEN);

        // validate group structure
        // counts number of children of each group
        let group_children_counts = vector[];
        params::right_pad_vec(&mut group_children_counts, NUM_GROUPS);
        // first, we count the signers as children
        signer_groups.for_each_ref(|group| {
            let group: u64 = *group as u64;
            assert!(group < NUM_GROUPS, E_OUT_OF_BOUNDS_GROUP);
            let count = group_children_counts.borrow_mut(group);
            *count += 1;
        });

        // second, we iterate backwards so as to check each group and propagate counts from
        // child group to parent groups up the tree to the root
        for (j in 0..NUM_GROUPS) {
            let i = NUM_GROUPS - j - 1;
            // ensure we have a well-formed group tree:
            // - the root should have itself as parent
            // - all other groups should have a parent group with a lower index
            let group_parent = group_parents[i] as u64;
            assert!(
                i == 0 || group_parent < i,
                E_GROUP_TREE_NOT_WELL_FORMED
            );
            assert!(
                i != 0 || group_parent == 0,
                E_GROUP_TREE_NOT_WELL_FORMED
            );

            let group_quorum = group_quorums[i];
            let disabled = group_quorum == 0;
            let group_children_count = group_children_counts[i];
            if (disabled) {
                // if group is disabled, ensure it has no children
                assert!(group_children_count == 0, E_SIGNER_IN_DISABLED_GROUP);
            } else {
                // if group is enabled, ensure group quorum can be met
                assert!(
                    group_children_count >= group_quorum, E_OUT_OF_BOUNDS_GROUP_QUORUM
                );

                // propagate children counts to parent group
                let count = group_children_counts.borrow_mut(group_parent);
                *count += 1;
            };
        };

        let multisig = borrow_multisig_mut(multisig_object(role));

        // remove old signer addresses
        multisig.signers = simple_map::new();
        multisig.config.signers = vector[];

        // save group quorums and parents to timelock
        multisig.config.group_quorums = group_quorums;
        multisig.config.group_parents = group_parents;

        // check signer addresses are in increasing order and save signers to timelock
        // evm zero address (20 bytes of 0) is the smallest address possible
        let prev_signer_addr = vector[];
        for (i in 0..signer_addresses.length()) {
            let signer_addr = signer_addresses[i];
            assert!(signer_addr.length() == 20, E_INVALID_SIGNER_ADDR_LEN);

            if (i > 0) {
                assert!(
                    params::vector_u8_gt(&signer_addr, &prev_signer_addr),
                    E_SIGNER_ADDR_MUST_BE_INCREASING
                );
            };

            let signer = Signer {
                addr: signer_addr,
                index: (i as u8),
                group: signer_groups[i]
            };
            multisig.signers.add(signer_addr, signer);
            multisig.config.signers.push_back(signer);
            prev_signer_addr = signer_addr;
        };

        if (clear_root) {
            // clearRoot is equivalent to overriding with a completely empty root
            let op_count = multisig.expiring_root_and_op_count.op_count;
            multisig.expiring_root_and_op_count = ExpiringRootAndOpCount {
                root: vector[],
                valid_until: 0,
                op_count
            };
            multisig.root_metadata = RootMetadata {
                role,
                chain_id: (chain_id::get() as u256),
                multisig: @mcms,
                pre_op_count: op_count,
                post_op_count: op_count,
                override_previous_root: true
            };
        };

        event::emit(
            ConfigSet { role, config: multisig.config, is_root_cleared: clear_root }
        );
    }

    public entry fun bypasser_execute_batch(
        caller: &signer,
        targets: vector<address>,
        module_names: vector<String>,
        function_names: vector<String>,
        datas: vector<vector<u8>>
    ) acquires Multisig, MultisigState, Timelock {
        let caller_address = signer::address_of(caller);
        assert!(
            is_bypasser(caller_address) || mcms_account::is_owner(caller_address),
            E_NOT_AUTHORIZED
        );

        for (i in 0..targets.length()) {
            let target = targets[i];
            let module_name = module_names[i];
            let function_name = function_names[i];
            let data = datas[i];

            dispatch_without_role(target, module_name, function_name, data);

            event::emit(
                BypasserCallExecuted { index: i, target, module_name, function_name, data }
            );
        };
    }

    public entry fun cancel(caller: &signer, id: vector<u8>) acquires MultisigState, Timelock {
        let caller_address = signer::address_of(caller);
        assert!(
            is_canceller(caller_address)
                || is_bypasser(caller_address)
                || mcms_account::is_owner(caller_address),
            E_NOT_AUTHORIZED
        );
        assert!(is_operation_pending(id), E_OPERATION_CANNOT_BE_CANCELLED);

        borrow_mut_timelock().timestamps.remove(id);
        event::emit(Cancelled { id });
    }

    public entry fun update_min_delay(
        caller: &signer, new_min_delay: u64
    ) acquires MultisigState, Timelock {
        let caller_address = signer::address_of(caller);
        assert!(
            is_bypasser(caller_address) || mcms_account::is_owner(caller_address),
            E_NOT_AUTHORIZED
        );

        let timelock = borrow_mut_timelock();
        let old_min_delay = timelock.min_delay;
        timelock.min_delay = new_min_delay;

        event::emit(MinDelayChange { old_min_delay, new_min_delay });
    }

    public fun get_blocked_function(index: u64): Function acquires Timelock {
        let timelock = borrow_timelock();
        assert!(
            index < smart_vector::length(&timelock.blocked_functions), E_INVALID_INDEX
        );
        *smart_vector::borrow(&timelock.blocked_functions, index)
    }

    fun is_function_blocked(
        target: address, module_name: String, function_name: String
    ): bool acquires Timelock {
        let timelock = borrow_timelock();
        for (i in 0..timelock.blocked_functions.length()) {
            let blocked_function = *smart_vector::borrow(&timelock.blocked_functions, i);
            if (params::target(blocked_function) == target
                && params::module_name(blocked_function) == module_name
                && params::function_name(blocked_function) == function_name) {
                return true
            };
        };
        false
    }

    #[view]
    /// Returns the registered multisig objects for the given role.
    public fun multisig_object(role: u8): Object<Multisig> acquires MultisigState {
        let state = borrow();
        if (role == BYPASSER_ROLE) {
            state.bypasser
        } else if (role == CANCELLER_ROLE) {
            state.canceller
        } else if (role == PROPOSER_ROLE) {
            state.proposer
        } else {
            abort E_INVALID_ROLE
        }
    }

    public entry fun block_function(
        caller: &signer,
        target: address,
        module_name: String,
        function_name: String
    ) acquires MultisigState, Timelock {
        let caller_address = signer::address_of(caller);
        assert!(
            is_bypasser(caller_address) || mcms_account::is_owner(caller_address),
            E_NOT_AUTHORIZED
        );

        let timelock = borrow_mut_timelock();
        let already_blocked = false;

        for (i in 0..smart_vector::length(&timelock.blocked_functions)) {
            let blocked_function = *smart_vector::borrow(&timelock.blocked_functions, i);
            if (params::target(blocked_function) == target
                && string::bytes(&params::module_name(blocked_function))
                    == module_name.bytes()
                && string::bytes(&params::function_name(blocked_function))
                    == function_name.bytes()) {
                already_blocked = true;
                break
            };
        };

        if (!already_blocked) {
            smart_vector::push_back(
                &mut timelock.blocked_functions,
                params::create_function(target, module_name, function_name)
            );
            event::emit(FunctionBlocked { target, module_name, function_name });
        };
    }

    public entry fun unblock_function(
        caller: &signer,
        target: address,
        module_name: String,
        function_name: String
    ) acquires MultisigState, Timelock {
        let caller_address = signer::address_of(caller);
        assert!(
            is_bypasser(caller_address) || mcms_account::is_owner(caller_address),
            E_NOT_AUTHORIZED
        );

        let timelock = borrow_mut_timelock();
        for (i in 0..smart_vector::length(&timelock.blocked_functions)) {
            let blocked_function = *smart_vector::borrow(&timelock.blocked_functions, i);
            if (params::target(blocked_function) == target
                && string::bytes(&params::module_name(blocked_function))
                    == module_name.bytes()
                && string::bytes(&params::function_name(blocked_function))
                    == function_name.bytes()) {
                smart_vector::swap_remove(&mut timelock.blocked_functions, i);
                event::emit(FunctionUnblocked { target, module_name, function_name });
                break
            };
        };
    }

    #[view]
    public fun is_operation(id: vector<u8>): bool acquires Timelock {
        let timelock = borrow_timelock();
        timelock.timestamps.contains(id) && *timelock.timestamps.borrow(id) > 0
    }

    #[view]
    public fun is_operation_pending(id: vector<u8>): bool acquires Timelock {
        let timelock = borrow_timelock();
        timelock.timestamps.contains(id)
            && *timelock.timestamps.borrow(id) > DONE_TIMESTAMP
    }

    #[view]
    public fun is_operation_ready(id: vector<u8>): bool acquires Timelock {
        let timelock = borrow_timelock();
        if (!timelock.timestamps.contains(id)) {
            return false
        };

        let timestamp_value = *timelock.timestamps.borrow(id);
        timestamp_value > DONE_TIMESTAMP && timestamp_value <= timestamp::now_seconds()
    }

    #[view]
    public fun is_operation_done(id: vector<u8>): bool acquires Timelock {
        let timelock = borrow_timelock();
        timelock.timestamps.contains(id)
            && *timelock.timestamps.borrow(id) == DONE_TIMESTAMP
    }

    #[view]
    public fun get_timestamp(id: vector<u8>): u64 acquires Timelock {
        let timelock = borrow_timelock();
        if (timelock.timestamps.contains(id)) {
            *timelock.timestamps.borrow(id)
        } else { 0 }
    }

    #[view]
    public fun is_bypasser(addr: address): bool acquires MultisigState {
        object::object_address(&borrow().bypasser) == addr
    }

    #[view]
    public fun is_canceller(addr: address): bool acquires MultisigState {
        object::object_address(&borrow().canceller) == addr
    }

    #[view]
    public fun is_proposer(addr: address): bool acquires MultisigState {
        object::object_address(&borrow().proposer) == addr
    }

    #[view]
    public fun get_config(role: u8): Config acquires MultisigState, Multisig {
        let multisig = multisig_object(role);
        borrow_multisig(multisig).config
    }

    public fun signers(multisig: Object<Multisig>): SimpleMap<vector<u8>, Signer> acquires Multisig {
        borrow_multisig(multisig).signers
    }

    #[view]
    public fun config(
        multisig: Object<Multisig>
    ): (vector<Signer>, vector<u8>, vector<u8>) acquires Multisig {
        let config = borrow_multisig(multisig).config;
        (config.signers, config.group_quorums, config.group_parents)
    }

    public fun role(root_metadata: RootMetadata): u8 {
        root_metadata.role
    }

    public fun chain_id(root_metadata: RootMetadata): u256 {
        root_metadata.chain_id
    }

    public fun root_metadata_multisig(root_metadata: RootMetadata): address {
        root_metadata.multisig
    }

    public fun pre_op_count(root_metadata: RootMetadata): u64 {
        root_metadata.pre_op_count
    }

    public fun post_op_count(root_metadata: RootMetadata): u64 {
        root_metadata.post_op_count
    }

    public fun override_previous_root(root_metadata: RootMetadata): bool {
        root_metadata.override_previous_root
    }

    #[view]
    public fun seen_signed_hashes(
        multisig: Object<Multisig>
    ): SimpleMap<vector<u8>, bool> acquires Multisig {
        borrow_multisig(multisig).seen_signed_hashes
    }

    #[view]
    /// Returns the current Merkle root along with its expiration timestamp and op count.
    public fun expiring_root_and_op_count(
        multisig: Object<Multisig>
    ): (vector<u8>, u64, u64) acquires Multisig {
        let multisig = borrow_multisig(multisig);
        (
            multisig.expiring_root_and_op_count.root,
            multisig.expiring_root_and_op_count.valid_until,
            multisig.expiring_root_and_op_count.op_count
        )
    }

    #[view]
    public fun root_metadata(multisig: Object<Multisig>): RootMetadata acquires Multisig {
        borrow_multisig(multisig).root_metadata
    }

    #[view]
    public fun num_groups(): u64 {
        NUM_GROUPS
    }

    #[view]
    public fun max_num_signers(): u64 {
        MAX_NUM_SIGNERS
    }

    #[view]
    public fun bypasser_role(): u8 {
        BYPASSER_ROLE
    }

    #[view]
    public fun canceller_role(): u8 {
        CANCELLER_ROLE
    }

    #[view]
    public fun proposer_role(): u8 {
        PROPOSER_ROLE
    }

    #[view]
    public fun min_delay(): u64 acquires Timelock {
        borrow_timelock().min_delay
    }

    #[view]
    public fun get_blocked_function_count(): u64 acquires Timelock {
        borrow_timelock().blocked_functions.length()
    }

    // computes keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA, metadata))
    inline fun hash_metadata_leaf(metadata: RootMetadata): vector<u8> {
        let role = params::encode_uint(metadata.role, 32);
        let chain_id = params::encode_uint(metadata.chain_id, 32);
        let multisig = bcs::to_bytes(&metadata.multisig);
        let pre_op_count = params::encode_uint(metadata.pre_op_count, 32);
        let post_op_count = params::encode_uint(metadata.post_op_count, 32);
        let override_previous_root =
            if (metadata.override_previous_root) {
                vector[1]
            } else {
                vector[0]
            };
        params::left_pad_vec(&mut override_previous_root, 32);

        let hash_preimage: vector<u8> = vector[];
        hash_preimage.append(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA);
        hash_preimage.append(role);
        hash_preimage.append(chain_id);
        hash_preimage.append(multisig);
        hash_preimage.append(pre_op_count);
        hash_preimage.append(post_op_count);
        hash_preimage.append(override_previous_root);
        // since we are using this in a merkle tree/proof, hash_preimage should be greater than 64 bytes
        // to prevent collisions with internal nodes. the above operations already guarantee this so no need to check.
        keccak256(hash_preimage)
    }

    inline fun borrow_multisig(obj: Object<Multisig>): &Multisig acquires Multisig {
        borrow_global<Multisig>(object::object_address(&obj))
    }

    inline fun borrow_multisig_mut(multisig: Object<Multisig>): &mut Multisig acquires Multisig {
        borrow_global_mut<Multisig>(object::object_address(&multisig))
    }

    inline fun borrow(): &MultisigState acquires MultisigState {
        freeze(borrow_mut())
    }

    inline fun borrow_mut(): &mut MultisigState acquires MultisigState {
        borrow_global_mut<MultisigState>(@mcms)
    }

    inline fun borrow_timelock(): &Timelock acquires Timelock {
        borrow_global<Timelock>(@mcms)
    }

    inline fun borrow_mut_timelock(): &mut Timelock acquires Timelock {
        borrow_global_mut<Timelock>(@mcms)
    }

    #[view]
    public fun is_valid_role(role: u8): bool {
        role < MAX_ROLE
    }

    public fun signer_view(signer_: &Signer): (vector<u8>, u8, u8) {
        (signer_.addr, signer_.index, signer_.group)
    }

    // ======================= TEST ONLY FUNCTIONS ======================= //

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun test_hash_metadata_leaf(
        role: u8,
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool
    ): vector<u8> {
        let metadata = RootMetadata {
            role,
            chain_id,
            multisig,
            pre_op_count,
            post_op_count,
            override_previous_root
        };
        hash_metadata_leaf(metadata)
    }

    #[test_only]
    public fun test_set_expiring_root_and_op_count(
        multisig: Object<Multisig>,
        root: vector<u8>,
        valid_until: u64,
        op_count: u64
    ) acquires Multisig {
        let multisig = borrow_multisig_mut(multisig);
        multisig.expiring_root_and_op_count.root = root;
        multisig.expiring_root_and_op_count.valid_until = valid_until;
        multisig.expiring_root_and_op_count.op_count = op_count;
    }

    #[test_only]
    public fun test_set_root_metadata(
        multisig: Object<Multisig>,
        role: u8,
        chain_id: u256,
        multisig_addr: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool
    ) acquires Multisig {
        let multisig = borrow_multisig_mut(multisig);
        multisig.root_metadata.role = role;
        multisig.root_metadata.chain_id = chain_id;
        multisig.root_metadata.multisig = multisig_addr;
        multisig.root_metadata.pre_op_count = pre_op_count;
        multisig.root_metadata.post_op_count = post_op_count;
        multisig.root_metadata.override_previous_root = override_previous_root;
    }

    #[test_only]
    /// For testing purposes, returns the signer for the given Multisigrole.
    public fun test_multisig_signer(role: u8): signer acquires MultisigState, Multisig {
        if (role == BYPASSER_ROLE) {
            let bypasser = borrow_mut().bypasser;
            multisig_signer(bypasser)
        } else if (role == CANCELLER_ROLE) {
            let canceller = borrow_mut().canceller;
            multisig_signer(canceller)
        } else if (role == PROPOSER_ROLE) {
            let proposer = borrow_mut().proposer;
            multisig_signer(proposer)
        } else {
            abort E_INVALID_ROLE
        }
    }
}
