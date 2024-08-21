module mcms::multisig {
    use std::signer;
    use std::vector;
    use std::option;
    use std::event;
    use std::bcs;
    use std::simple_map::{SimpleMap,Self};
    use std::secp256k1;
    use std::aptos_hash::keccak256;
    use aptos_framework::multisig_account;
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::timestamp;

    const MULTISIG_SEED: vector<u8> = b"CHAINLINK_MCMS_MULTISIG";

    // MCM Consts
    const NUM_GROUPS: u8 = 32;
    const MAX_NUM_SIGNERS: u8 = 200;
    // equivalent to address(0x0) in Solidity
    const ZERO_EVM_ADDRESS: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // equivalent to initializing empty uint8[NUM_GROUPS] in Solidity
    const VEC_NUM_GROUPS: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // keccak256("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA")
    const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA: vector<u8> = x"e6b82be989101b4eb519770114b997b97b3c8707515286748a871717f0e4ea1c";
    // keccak256("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP")
    const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP: vector<u8> = x"08d275622006c4ca82d03f498e90163cafd53c663a48470c3b52ac8bfbd9f52c";

    // Error Codes
    const ERR: u64 = 0; // generic error
    const ENO_MULTISIG: u64 = 1;
    const EALREADY_SEEN_HASH: u64 = 2;
    // execute errors
    const EPOST_OP_COUNT_REACHED: u64 = 3;
    const EWRONG_CHAIN_ID: u64 = 4;
    const EWRONG_MULTISIG: u64 = 5;
    const EROOT_EXPIRED: u64 = 6;
    const EWRONG_NONCE: u64 = 7;
    // set_root errors
    const EVALID_UNTIL_EXPIRED: u64 = 8;
    const EINVALID_SIGNER: u64 = 9;
    const EMISSING_CONFIG: u64 = 10;
    const EINSUFFICIENT_SIGNERS: u64 = 11;
    const EPROOF_CANNOT_BE_VERIFIED: u64 = 12;
    const EPENDING_OPS: u64 = 13;
    const EWRONG_PRE_OP_COUNT: u64 = 14;
    const EWRONG_POST_OP_COUNT: u64 = 15;
    // set_config errors
    const EINVALID_NUM_SIGNERS: u64 = 9;
    const ESIGNER_GROUPS_LEN_MISMATCH: u64 = 10;
    const EINVALID_GROUP_QUORUM_LEN: u64 = 11;
    const EINVALID_GROUP_PARENTS_LEN: u64 = 12;
    const EOUT_OF_BOUNDS_GROUP: u64 = 13;
    const EGROUP_TREE_NOT_WELL_FORMED: u64 = 14;
    const ESIGNER_IN_DISABLED_GROUP: u64 = 15;
    // const ENO_SIGNERS_IN_GROUP: u64 = 16;
    const EOUT_OF_BOUNDS_GROUP_QUORUM: u64 = 17;
    const ESIGNER_ADDR_MUST_BE_INCREASING: u64 = 18;
    // miscellanous
    const ECMP_VECTORS_DIFF_LEN: u64 = 100;
    const EINVALID_V_SIGNATURE: u64 = 101;
    const EFAILED_ECDSA_RECOVER: u64 = 102;
    const EINVALID_ROOT_LEN: u64 = 103;
    const EUNATHORIZED: u64 = 104;

    // MCM Structs
    struct RootMetadata has key, store, copy, drop {
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool
    }

    struct Op has copy, drop {
        chain_id: u256,
        multisig: address,
        nonce: u64,
        data: vector<u8>
    }

    struct Signer has store, copy, drop {
        addr: vector<u8>,
        index: u8, // index of signer in s_config.signers
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

    // todo: Since only an owner of the internal multisig account can execute the final
    // transaction, we have to define and save an executor signer which is the only account
    // that can execute the transaction. the internal multisig will be a 2-of-2 multisig
    // where MCMS is one signer and the executor is the other signer. MCMS does not expose
    // any methods to vote on transactions, and thus any txs proposed by the executor will
    // never be able to be executed. this changes the MCMS model from (k of n) to ((k of n) +1)
    // if we explore using the Aptos native multisig account (1 of N) as an executor, this 
    // can make it effectively more than one single signer, but this is still different to
    // to original behaviour of MCMS on EVM chains.

    struct MCMState has key, store, drop {
        // s_signers is used to easily validate the existence of the signer by its address. We still
        // have signers stored in s_config in order to easily deactivate them when a new config is set.
        s_signers: SimpleMap<vector<u8>, Signer>,

        s_config: Config,

        // Remember signedHashes that this contract has seen. Each signedHash can only be set once.
        s_seen_signed_hashes: SimpleMap<vector<u8>, bool>,

        s_expiring_root_and_op_count: ExpiringRootAndOpCount,

        s_root_metadata: RootMetadata,

        // Aptos extended multisig fields
        addr: address,

        signer_cap: account::SignerCapability,

        // Ownable fields
        owner: address
	}

    #[event]
    struct ConfigSet has drop, store {
        config: Config,
        is_root_cleared: bool
    }

    #[event]
    struct NewRoot has drop, store {
        root: vector<u8>,
        valid_until: u64,
        metadata: RootMetadata
    }

    #[event]
    struct OpExecuted has drop, store {
        nonce: u64,
        data: vector<u8>,
    }


    // MCM Getters 

    #[view]
    public fun get_config(): Config acquires MCMState {
        borrow_global<MCMState>(get_state_addr()).s_config
    }

    #[view]
    public fun get_op_count(): u64 acquires MCMState {
        borrow_global<MCMState>(get_state_addr()).s_expiring_root_and_op_count.op_count
    }

    #[view]
    public fun get_root(): (vector<u8>, u64) acquires MCMState {
        let state = borrow_global<MCMState>(get_state_addr());
        (state.s_expiring_root_and_op_count.root, state.s_expiring_root_and_op_count.valid_until)
    }

    #[view]
    public fun get_root_metadata(): RootMetadata acquires MCMState {
        borrow_global<MCMState>(get_state_addr()).s_root_metadata
    }

    // Ownable getters

    #[view]
    public fun owner(): address acquires MCMState {
        borrow_global<MCMState>(get_state_addr()).owner
    }
    
    // Getters to help manage the wrapped extended multisig account

    #[view]
    public fun get_multisig_addr(): address acquires MCMState {
        assert!(exists<MCMState>(get_state_addr()), ENO_MULTISIG);
        borrow_global<MCMState>(get_state_addr()).addr
    }

    #[view]
    public fun get_pending_transactions(): vector<multisig_account::MultisigTransaction> acquires MCMState {
        multisig_account::get_pending_transactions(get_multisig_addr())
    }

    #[view]
    public fun get_transaction(sequence_number: u64): multisig_account::MultisigTransaction acquires MCMState {
        multisig_account::get_transaction(get_multisig_addr(), sequence_number)
    }

    #[view]
    public fun get_last_resolved_sequence_number(): u64 acquires MCMState {
        multisig_account::last_resolved_sequence_number(get_multisig_addr())
    }

    #[view]
    public fun get_next_sequence_number(): u64 acquires MCMState {
        multisig_account::next_sequence_number(get_multisig_addr())
    }

    // MCM Functions
    public entry fun set_root(
        root: vector<u8>,
        valid_until: u64,
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool,
        metadata_proof: vector<vector<u8>>,
        signatures: vector<vector<u8>>
    ) acquires MCMState {
        let metadata = RootMetadata { 
            chain_id,
            multisig,
            pre_op_count,
            post_op_count,
            override_previous_root
        };
        let state = borrow_global_mut<MCMState>(get_state_addr());
        // also checks root = 32 bytes
        let signed_hash = compute_eth_message_hash(root, valid_until);

        // check if hash has been seen already
        assert!(simple_map::contains_key(&mut state.s_seen_signed_hashes, &signed_hash) == false, EALREADY_SEEN_HASH);

        // verify valid_until against current timestamp
        assert!(timestamp::now_seconds() <= valid_until, EVALID_UNTIL_EXPIRED);

        // verify chain id
        assert!(metadata.chain_id == (chain_id::get() as u256), EWRONG_CHAIN_ID);

        // verify mcms address
        assert!(metadata.multisig == @mcms, EWRONG_MULTISIG);

        // verify op counts
        let op_count = state.s_expiring_root_and_op_count.op_count;
        // don't allow a new root to be set if there are still outstanding ops that have not been
        // executed, unless overridePreviousRoot is set
        assert!(override_previous_root || op_count == state.s_root_metadata.post_op_count, EPENDING_OPS);
        // the signers are responsible for tracking opCount offchain and ensuring that
        // preOpCount equals to opCount and preOpCount <= postOpCount 
        assert!(op_count == metadata.pre_op_count, EWRONG_PRE_OP_COUNT);
        assert!(metadata.pre_op_count <= metadata.post_op_count, EWRONG_POST_OP_COUNT);

        // verify metadata proof
        {
            let hashed_leaf: vector<u8> = hash_metadata_leaf(metadata);
            assert!(verify_merkle_proof(metadata_proof, root, hashed_leaf), EPROOF_CANNOT_BE_VERIFIED);
        };

        // verify ECDSA signatures on (root, valid_until) and ensure that the root group is successful
        {
            // verify sigs and count number of signers in each group
            let signer: Signer;
            let prev_address: vector<u8> = ZERO_EVM_ADDRESS;
            let group_vote_counts: vector<u8> = right_pad_vec(vector[], NUM_GROUPS);
            vector::for_each(signatures, |signature| {
                let signer_addr = ecdsa_recover_evm_addr(signed_hash, signature);
                // the off-chain system is required to sort the signatures by the
                // signer address in an increasing order
                assert!(vector_u8_gt(signer_addr, prev_address), ESIGNER_ADDR_MUST_BE_INCREASING);
                prev_address = signer_addr;

                assert!(simple_map::contains_key(&state.s_signers, &signer_addr), EINVALID_SIGNER);
                signer = *simple_map::borrow(&state.s_signers, &signer_addr);

                // check group quorums
                let group: u8 = signer.group;
                while (true) {
                    let group_vote_count = vector::borrow_mut(&mut group_vote_counts, (group as u64));
                    *group_vote_count = *group_vote_count + 1;

                    let quorum = vector::borrow(&state.s_config.group_quorums, (group as u64));
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
                    group = *vector::borrow(&state.s_config.group_parents, (group as u64));
                };
            });

            // the group at the root of the tree (with index 0) determines whether the vote passed,
            // we cannot proceed if it isn't configured with a valid (non-zero) quorum
            let root_group_quorum = vector::borrow(&state.s_config.group_quorums, 0);
            assert!(*root_group_quorum != 0, EMISSING_CONFIG);

            // check root group reached quorum
            let root_group_vote_count = vector::borrow(&group_vote_counts, 0);
            assert!(*root_group_vote_count >= *root_group_quorum, EINSUFFICIENT_SIGNERS);
        };

        // save details to contract state     
        simple_map::add(&mut state.s_seen_signed_hashes, signed_hash, true);
        state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
            root,
            valid_until,
            op_count: metadata.pre_op_count
        };
        state.s_root_metadata = metadata;
        event::emit(NewRoot { root, valid_until, metadata });
    }

    // note: unlike MCM on EVM chains, this function does not actually execute the transaction,
    // but rather creates the transaction on the multisig account to be executed in a separate tx
    public entry fun execute(
        chain_id: u256,
        multisig: address,
        nonce: u64,
        data: vector<u8>,
        proof: vector<vector<u8>>
    ) acquires MCMState {
        let state = borrow_global_mut<MCMState>(get_state_addr());
        let op = Op {
            chain_id,
            multisig,
            nonce,
            data
        };

        // op validations
        assert!(state.s_root_metadata.post_op_count > state.s_expiring_root_and_op_count.op_count, EPOST_OP_COUNT_REACHED);

        assert!(op.chain_id == (chain_id::get() as u256), EWRONG_CHAIN_ID);

        assert!(op.multisig == @mcms, EWRONG_MULTISIG);

        assert!(timestamp::now_seconds() <= state.s_expiring_root_and_op_count.valid_until, EROOT_EXPIRED);

        assert!(op.nonce == state.s_expiring_root_and_op_count.op_count, EWRONG_NONCE);

        // verify op exists in merkle tree
        let hashed_leaf: vector<u8> = hash_op_leaf(op);
        assert!(verify_merkle_proof(proof, state.s_expiring_root_and_op_count.root, hashed_leaf), EPROOF_CANNOT_BE_VERIFIED);

        // increment op_count
        state.s_expiring_root_and_op_count.op_count = state.s_expiring_root_and_op_count.op_count + 1;

        // create transaction on multisig account (will already have one approval from creator)
        // todo: investigate if `to` params are encoded in the `data` payload
        let multisig_addr = get_multisig_addr();
        let multisig_signer = multisig_signer();
        multisig_account::create_transaction_with_hash(&multisig_signer, multisig_addr, data);

        event::emit(OpExecuted {
            nonce: op.nonce,
            data: op.data,
        })
    }

    public entry fun set_config(
        resource_account: &signer,
        signer_addresses: vector<vector<u8>>,
        signer_groups: vector<u8>,
        group_quorums: vector<u8>,
        group_parents: vector<u8>,
        clear_root: bool
    ) acquires MCMState {
        only_owner(resource_account);

        assert!(vector::length(&signer_addresses) != 0 && vector::length(&signer_addresses) <= (MAX_NUM_SIGNERS as u64), EINVALID_NUM_SIGNERS);
        assert!(vector::length(&signer_addresses) == vector::length(&signer_groups), ESIGNER_GROUPS_LEN_MISMATCH);
        assert!(vector::length(&group_quorums) == (NUM_GROUPS as u64), EINVALID_GROUP_QUORUM_LEN);
        assert!(vector::length(&group_parents) == (NUM_GROUPS as u64), EINVALID_GROUP_PARENTS_LEN);

        // validate group structure
        // counts number of children of each group
        let group_children_counts = right_pad_vec(vector[], NUM_GROUPS);
        // first, we count the signers as children
        vector::for_each(signer_groups, |group| {
            assert!(group < NUM_GROUPS, EOUT_OF_BOUNDS_GROUP);
            let count = vector::borrow_mut(&mut group_children_counts, (group as u64));
            *count = *count + 1;
        });

        // second, we iterate backwards so as to check each group and propagate counts from
        // child group to parent groups up the tree to the root
        let j: u8 = 0;
        while (j < NUM_GROUPS) {
            let i = NUM_GROUPS - j - 1;
            // ensure we have a well-formed group tree:
            // - the root should have itself as parent
            // - all other groups should have a parent group with a lower index
            let group_parent = vector::borrow(&group_parents, (i as u64));
            assert!(i == 0 || *group_parent < i, EGROUP_TREE_NOT_WELL_FORMED);
            assert!(i != 0 || *group_parent == 0, EGROUP_TREE_NOT_WELL_FORMED);

            let group_quorum = vector::borrow(&group_quorums, (i as u64));
            let disabled = *group_quorum == 0;
            let group_children_count = vector::borrow(&group_children_counts, (i as u64));
            if (disabled) {
                // if group is disabled, ensure it has no children
                assert!(*group_children_count == 0, ESIGNER_IN_DISABLED_GROUP);
            } else {
                // if group is enabled, ensure group quorum can be met
                let group_quorum = vector::borrow(&group_quorums, (i as u64));
                assert!(*group_children_count >= *group_quorum, EOUT_OF_BOUNDS_GROUP_QUORUM);

                // propagate children counts to parent group
                let count = vector::borrow_mut(&mut group_children_counts, (*group_parent as u64));
                *count = *count + 1;
            };

            j = j + 1;
        };

        // remove old signer addresses
        let state = borrow_global_mut<MCMState>(get_state_addr());
        while (!vector::is_empty(&state.s_config.signers)) {
            let old_signer: Signer = vector::pop_back(&mut state.s_config.signers);
            simple_map::remove(&mut state.s_signers, &old_signer.addr);
        };
        assert!(vector::length(&state.s_config.signers) == 0, ERR);

        // save group quorums and parents to state
        state.s_config.group_quorums = group_quorums;
        state.s_config.group_parents = group_parents;

        // check signer addresses are in increasing order and save signers to state
        // evm zero address (20 bytes of 0) is the smallest address possible
        let prev_signer_addr: vector<u8> = ZERO_EVM_ADDRESS;
        let i = 0;
        while (i < vector::length(&signer_addresses)) {
            let signer_addr = vector::borrow(&signer_addresses, (i as u64));
            // this line checks:
            // - signer address is exactly 20 bytes
            // - signer is distinct
            // - signer address is in increasing order
            assert!(vector_u8_gt(*signer_addr, prev_signer_addr), ESIGNER_ADDR_MUST_BE_INCREASING);

            let signer = Signer {
                addr: *signer_addr,
                index: (i as u8),
                group: *vector::borrow(&signer_groups, (i as u64))
            };
            simple_map::add(&mut state.s_signers, *signer_addr, signer);
            vector::push_back(&mut state.s_config.signers, signer);
            prev_signer_addr = *signer_addr;
            i = i + 1;
        };

        if (clear_root) {
            // clearRoot is equivalent to overriding with a completely empty root
            let op_count = state.s_expiring_root_and_op_count.op_count;
            state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
                root: vector[],
                valid_until: 0,
                op_count
            };
            state.s_root_metadata = RootMetadata {
                chain_id: (chain_id::get() as u256),
                multisig: get_state_addr(),
                pre_op_count: op_count,
                post_op_count: op_count,
                override_previous_root: true
            };
        };

        event::emit(ConfigSet { config: state.s_config, is_root_cleared: clear_root });
    }

    // Ownable functions

    fun transfer_ownership(resource_account: &signer, new_owner: address) acquires MCMState {
        only_owner(resource_account);
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.owner = new_owner;
    }

    // Internal functions
    fun init_module(account: &signer) {
        // We can't use objects here because the owner of a multisig account needs to have the Account resource
        // at least during multisig creation:
        // https://github.com/aptos-labs/aptos-core/blob/bd4e8c53db3b6a70f3ff04b02be754166fc87cc4/aptos-move/framework/aptos-framework/sources/multisig_account.move#L1262
        assert!(signer::address_of(account) == @mcms, 1);
        let (resource_signer, resource_signer_cap) = account::create_resource_account(account, MULTISIG_SEED);
        let resource_address = signer::address_of(&resource_signer);

        // derive internal multisig address
        let multisig_addr = multisig_account::get_next_multisig_account_address(resource_address);
        // create multisig account with the resource account and @owner as owners, requiring 2 signatures.
        // this is necessary because we need an EOA account to execute the 0x1::multisig_account transaction.
        multisig_account::create_with_owners(&resource_signer, vector[@owner], 2, vector[], vector[]);

        move_to(&resource_signer, MCMState {
            s_signers: simple_map::new(),
            s_config: Config { signers: vector[], group_quorums: VEC_NUM_GROUPS, group_parents: VEC_NUM_GROUPS },
            s_seen_signed_hashes: simple_map::new(),
            s_expiring_root_and_op_count: ExpiringRootAndOpCount { root: vector[], valid_until: 0, op_count: 0 },
            s_root_metadata: RootMetadata { chain_id: 0, multisig: get_state_addr(), pre_op_count: 0, post_op_count: 0, override_previous_root: false },
            addr: multisig_addr,
            signer_cap: resource_signer_cap,
            owner: @owner,
        });
    }

    fun get_state_addr(): address {
        account::create_resource_address(&@mcms, MULTISIG_SEED)
    }

    fun ecdsa_recover_evm_addr(eth_signed_message_hash: vector<u8>, signature: vector<u8>): vector<u8> {
        // ensure signature has correct length - (r,s,v) concatenated = 65 bytes
        assert!(vector::length(&signature) == 65, ERR);
        // extract v from signature
        let v = vector::pop_back(&mut signature);
        // convert 64 byte signature into ECDSASignature struct
        let sig = secp256k1::ecdsa_signature_from_bytes(signature);
        // Aptos uses the rust libsecp256k1 parse() under the hood which has a different numbering scheme
        // see: https://docs.rs/libsecp256k1/latest/libsecp256k1/struct.RecoveryId.html#method.parse_rpc
        assert!(v >= 27 && v < 27 + 4, EINVALID_V_SIGNATURE);
        let v = v - 27;

        // retrieve signer public key
        let public_key = aptos_std::secp256k1::ecdsa_recover(
            eth_signed_message_hash,
            v,
            &sig,
        );
        assert!(option::is_some(&public_key), EFAILED_ECDSA_RECOVER);

        // return last 20 bytes of hashed public key as the recovered ethereum address
        let public_key_bytes = secp256k1::ecdsa_raw_public_key_to_bytes(&option::extract(&mut public_key));
        std::vector::trim((&mut keccak256(public_key_bytes)), 12) // trims publicKeyBytes to 12 bytes, returns trimmed last 20 bytes
    }

    fun compute_eth_message_hash(root: vector<u8>, valid_until: u64): vector<u8> {
        // abi.encode(root (bytes32), valid_until)
        let valid_until_bytes = left_pad_vec(uint_to_bytes(valid_until), 32);
        assert!(vector::length(&root) == 32, EINVALID_ROOT_LEN); // root should be 32 bytes
        let abi_encoded_params = &mut root; 
        vector::append(abi_encoded_params, valid_until_bytes);

        // keccak256(abi_encoded_params)
        let hashed_encoded_params = keccak256(*abi_encoded_params);

        // ECDSA.toEthSignedMessageHash()
        let eth_msg_prefix = b"\x19Ethereum Signed Message:\n32";
        let hash = &mut eth_msg_prefix;
        vector::append(hash, hashed_encoded_params);
        keccak256(*hash)
    }

    // computes keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA, metadata))
    fun hash_metadata_leaf(metadata: RootMetadata): vector<u8> {
        let chain_id = left_pad_vec(uint_to_bytes(metadata.chain_id), 32);
        let multisig = bcs::to_bytes(&metadata.multisig);
        let pre_op_count = left_pad_vec(uint_to_bytes(metadata.pre_op_count), 32);
        let post_op_count = left_pad_vec(uint_to_bytes(metadata.post_op_count), 32);
        // let override_previous_root = left_pad_vec(uint_to_bytes(metadata.override_previous_root as u8), 32);
        let override_previous_root: vector<u8>;
        if (metadata.override_previous_root) {
            override_previous_root = vector[1];
        } else {
            override_previous_root = vector[0];
        };
        
        let hash_preimage: vector<u8> = vector[];
        vector::append(&mut hash_preimage, MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA);
        vector::append(&mut hash_preimage, chain_id);
        vector::append(&mut hash_preimage, multisig);
        vector::append(&mut hash_preimage, pre_op_count);
        vector::append(&mut hash_preimage, post_op_count);
        vector::append(&mut hash_preimage, left_pad_vec(override_previous_root, 32));
        // since we are using this in a merkle tree/proof, hash_preimage should be greater than 64 bytes
        // to prevent collisions with internal nodes. the above operations already guarantee this so no need to check.
        keccak256(hash_preimage)
    }

    // computes keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP, op))
    fun hash_op_leaf(op: Op): vector<u8> {
        let chain_id = left_pad_vec(uint_to_bytes(op.chain_id), 32);
        let multisig = bcs::to_bytes(&op.multisig);
        let nonce = left_pad_vec(uint_to_bytes(op.nonce), 32);

        let hash_preimage: vector<u8> = vector[];
        vector::append(&mut hash_preimage, MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP);
        vector::append(&mut hash_preimage, chain_id);
        vector::append(&mut hash_preimage, multisig);
        vector::append(&mut hash_preimage, nonce);
        vector::append(&mut hash_preimage, op.data);

        // right pad op.data to multiple of 32 bytes
        // note that we can't use right_pad_vec which takes a u8 as length.
        let pad_amount = 32 - (vector::length(&op.data) % 32);
        while (pad_amount > 0) {
          vector::push_back(&mut hash_preimage, 0);
          pad_amount = pad_amount - 1;
        };

        // since we are using this in a merkle tree/proof, hash_preimage should be greater than 64 bytes
        // to prevent collisions with internal nodes. the above operations already guarantee this so no need to check.
        keccak256(hash_preimage)
    }

    fun verify_merkle_proof(proof: vector<vector<u8>>, root: vector<u8>, leaf: vector<u8>): bool {
        let computed_hash = leaf;
        vector::for_each(proof, |proof_element| {
            let left = computed_hash;
            let right = proof_element;
            if (vector_u8_gt(computed_hash, proof_element)) {
                left = proof_element;
                right = computed_hash;
            };
            let hash_input: vector<u8> = left;
            vector::append(&mut hash_input, right);
            computed_hash = keccak256(hash_input);
        });
        computed_hash == root
    }

    // retrieve signer for multisig account - should be protected with appropriate guards
    fun multisig_signer(): signer acquires MCMState {
        assert!(exists<MCMState>(get_state_addr()), ENO_MULTISIG);
        account::create_signer_with_capability(&borrow_global<MCMState>(get_state_addr()).signer_cap)
    }

    // helper function to convert any input type to bytes
    // note: does not remove leading zero bytes, however this is fine as we are using this in the
    // context of computing hashes where we left pad to 32 bytes anyway.
    fun uint_to_bytes<T: drop>(input: T): vector<u8> {
        let bcs_bytes = bcs::to_bytes(&input);
        vector::reverse(&mut bcs_bytes);
        bcs_bytes
    }

    // helper function to right pad a vector<u8> with zero bytes to a specified length
    // this function returns the input if the input length is already equal to or greater than num_bytes
    fun right_pad_vec(input: vector<u8>, num_bytes: u8): vector<u8> {
        let len = vector::length(&input);
        if (len >= (num_bytes as u64)) {
            return input
        };
        let bytes_to_pad = (num_bytes as u64) - len;
        let padded: vector<u8> = copy input;
        let i = 0;
        while (i < bytes_to_pad) {
            vector::push_back(&mut padded, 0);
            i = i + 1;
        };
        padded
    }

    // helper function to left pad a vector<u8> with zero bytes to a specified length
    // this function returns the input if the input length is already equal to or greater than num_bytes
    fun left_pad_vec(input: vector<u8>, num_bytes: u8): vector<u8> {
        let len = vector::length(&input);
        if (len >= (num_bytes as u64)) {
            return input
        };
        let bytes_to_pad = (num_bytes as u64) - len;
        let padded: vector<u8> = vector[];
        let i = 0;
        while (i < bytes_to_pad) {
            vector::push_back(&mut padded, 0);
            i = i + 1;
        };
        vector::append(&mut padded, input);
        padded
    }

    // helper function to compare two vector<u8> values. expects both vectors to be of equal length.
    // returns true if a > b, false otherwise
    fun vector_u8_gt(a: vector<u8>, b: vector<u8>): bool {
        let len = vector::length(&a);
        assert!(len == vector::length(&b), ECMP_VECTORS_DIFF_LEN);

        // reverse vectors to compare from most significant bytes first
        let rev_a = copy a;
        let rev_b = copy b;
        vector::reverse(&mut rev_a);
        vector::reverse(&mut rev_b);

        // compare each byte until not equal
        while (!vector::is_empty(&rev_a)) {
            let byte_a = vector::pop_back(&mut rev_a);
            let byte_b = vector::pop_back(&mut rev_b);
            if (byte_a > byte_b) {
                return true
            } else if (byte_a < byte_b) {
                return false
            };
        };

        // vectors are equal, a == b
        false
    }

    fun only_owner(caller: &signer) acquires MCMState {
        let state = borrow_global<MCMState>(get_state_addr());
        assert!(state.owner == signer::address_of(caller), EUNATHORIZED);
    }

    //// TESTS ////

    #[test_only]
    use aptos_framework::coin;
    #[test_only]
    use aptos_framework::aptos_coin;

    #[test_only]
    const CHAIN_ID: u8 = 1;
    #[test_only]
    const TIMESTAMP: u64 = 1724800000;

    // EVM addresses 1 - 3 in ascending order
    #[test_only]
    const ADDR1: vector<u8> = x"2069635ab34ee4d99f6ef34407537be69aa99bc3";
    #[test_only]
    const ADDR2: vector<u8> = x"adfd44bce6cf8e7fe34e5db1b8d2e8ff1dc14312";
    #[test_only]
    const ADDR3: vector<u8> = x"b95de8d1bea412311e64a25e1fdfd84f08c02cca";

    // test config: 2-of-3 multisig
    #[test_only]
    const SIGNER_GROUPS: vector<u8> = vector[1, 2, 3];
    #[test_only]
    const GROUP_QUORUMS: vector<u8> = vector[2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    #[test_only]
    const GROUP_PARENTS: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // test set root params
    #[test_only]
    const ROOT: vector<u8> = x"1a96ff82e6d0a7cea26e12f2c6d19ec784e11cb14f19da5e45061e9e254c1c52";

    #[test_only]
    const VALID_UNTIL: u64 = 1724809164;

    #[test_only]
    const PRE_OP_COUNT: u64 = 0;
    #[test_only]
    const POST_OP_COUNT: u64 = 3;

    #[test_only]
    const METADATA_PROOF: vector<vector<u8>> = vector[
      x"876ca709f922f97afc2e7722782923bfe9da9c15c236870494e4a21ee385b94b",
      x"3482dfbe0856d5c5399fe5afae0ba8cf127f4a54b8da6571f061fc933436ec38"
    ];

    // cannot generate secp256k1 signatures in Move for testing so need to hard code
    #[test_only]
    const SIGNATURES: vector<vector<u8>> = vector[
        x"4cea287be319937950431b32e6b36d358ff62dcc47ee735f1481a7275f8d3d8a7ad5827005270d83f2ba7e45a14c599353213d1c6f2c298365a5d9ba20e00b971b",
        x"de12f77acccc12615541a8b69b26a6351cd2e225e8177c447bcc6734dd7b736b679f46d6e51d3f3db930f6ff98fb6430d8c50e6deedb28bc7895ba89528fc75c1b",
        x"8e01e215ec8d7f391884ebf7a4aec05d8c1e40abd3183b6d39202f391f53e0370263c47793c348b0e86c0646d47b256f563fff91029af3eb3fa07c857f0d04901c",
    ];

    #[test_only]
    // test execute params
    const LEAVES: vector<vector<u8>> = vector[
        x"75a7dc4ac036b3e4478b62d3a4fb446b298c9d429c94c10cc8758a052b055bdc", // index 0
        x"876ca709f922f97afc2e7722782923bfe9da9c15c236870494e4a21ee385b94b", // index 1
        x"171ec02e28e71b310c020ed2d1d3eb6927c6ade0b52b37f8599390edddc8e6c6", // index 2
        x"10dfeb49c9a869d351db29caca5f2d31b072d0b3fec3c98f82a70626b1d71875"  // index 3
    ];

    #[test_only]
    const OP1_PROOF: vector<vector<u8>> = vector[
        x"75a7dc4ac036b3e4478b62d3a4fb446b298c9d429c94c10cc8758a052b055bdc",
        x"3482dfbe0856d5c5399fe5afae0ba8cf127f4a54b8da6571f061fc933436ec38"
    ];
    #[test_only]
    const OP1_NONCE: u64 = 0;
    #[test_only]
    const OP1_DATA: vector<u8> = b"This is exactly 32 bytes long...";


    #[test_only]
    fun setup(deployer: &signer, framework: &signer): address {
        // setup aptos coin for test
        let (burn, mint) = aptos_coin::initialize_for_test(framework);
        coin::destroy_mint_cap(mint);
        coin::destroy_burn_cap(burn);
        // setup deployer account for test
        let deployer_addr = signer::address_of(deployer);
        aptos_framework::account::create_account_for_test(deployer_addr);

        // setup test components
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);
        chain_id::initialize_for_test(framework, CHAIN_ID);

        // init multisig using internal fn as we cant use retrieve_resource_account_cap in a test (error: ECONTAINER_NOT_PUBLISHED)
        init_module(deployer);

        get_state_addr()
    }

    // helper struct for execute args in tests
    #[test_only]
    struct ExecuteArgs has drop {
        chain_id: u256,
        multisig: address,
        nonce: u64,
        data: vector<u8>,
        proof: vector<vector<u8>>
    }

    #[test_only]
    fun default_execute_args(): ExecuteArgs {
        ExecuteArgs {
            chain_id: (CHAIN_ID as u256),
            multisig: @mcms,
            nonce: OP1_NONCE,
            data: OP1_DATA,
            proof: OP1_PROOF
        }
    }

    #[test_only]
    fun call_execute(args: ExecuteArgs) acquires MCMState {
        execute(args.chain_id, args.multisig, args.nonce, args.data, args.proof);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    public entry fun test_e2e(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);

        // set config
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);

        // set root
        let set_root_args = default_set_root_args();
        call_set_root(set_root_args);

        // check pending txs on the wrapped multisig
        let pending_txs = get_pending_transactions();
        assert!(vector::length(&pending_txs) == 0, 0);

        // check op count
        let op_count = get_op_count();
        assert!(op_count == 0, 1);

        // execute op (creates transaction on multisig)
        let execute_args = default_execute_args();
        call_execute(execute_args);

        // check pending txs on the wrapped multisig
        let pending_txs = get_pending_transactions();
        assert!(vector::length(&pending_txs) == 1, 2);

        // check op count incremented
        let op_count = get_op_count();
        assert!(op_count == 1, 3);

        // check tx can be executed by provided multisig owner. can_be_executed() is expected
        // to return false since @owner (the EOA) gives its vote when broadcasting the
        // transaction.
        let multisig_address = get_multisig_addr();
        assert!(!multisig_account::can_be_executed(multisig_address, 1), 4);
        assert!(multisig_account::can_execute(@owner, multisig_address, 1), 5);
    }

    //// set_root tests ////

    // helper struct for set_root args in tests
    #[test_only]
    struct SetRootArgs has drop {
        root: vector<u8>,
        valid_until: u64,
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool,
        metadata_proof: vector<vector<u8>>,
        signatures: vector<vector<u8>>
    }

    #[test_only]
    fun default_set_root_args(): SetRootArgs {
        SetRootArgs {
            root: ROOT,
            valid_until: VALID_UNTIL,
            chain_id: (CHAIN_ID as u256), 
            multisig: @mcms,
            pre_op_count:  PRE_OP_COUNT,
            post_op_count: POST_OP_COUNT,
            override_previous_root: false,
            metadata_proof: METADATA_PROOF,
            signatures: SIGNATURES
        }
    }

    #[test_only]
    fun call_set_root(args: SetRootArgs) acquires MCMState {
        set_root(args.root, args.valid_until, args.chain_id, args.multisig, args.pre_op_count, args.post_op_count, args.override_previous_root, args.metadata_proof, args.signatures);
    }

    // test helper function to generate the merkle root for given metadata
    #[test_only]
    fun compute_root(metadata: RootMetadata): vector<u8> {
        let leaf = hash_metadata_leaf(metadata);
        let computed_hash = leaf;
        vector::for_each(METADATA_PROOF, |proof_element| {
            let left = computed_hash;
            let right = proof_element;
            if (vector_u8_gt(computed_hash, proof_element)) {
                left = proof_element;
                right = computed_hash;
            };
            let hash_input: vector<u8> = left;
            vector::append(&mut hash_input, right);
            computed_hash = keccak256(hash_input);
        });
        computed_hash
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EALREADY_SEEN_HASH)]
    public entry fun test_set_root__already_seen_hash(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);

        // first call success
        let set_root_args = default_set_root_args();
        call_set_root(set_root_args);

        // second call should fail as the hash has already been seen
        let set_root_args2 = default_set_root_args();
        call_set_root(set_root_args2);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EVALID_UNTIL_EXPIRED)]
    public entry fun test_set_root__valid_until_expired(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let set_root_args = default_set_root_args();
        set_root_args.valid_until = TIMESTAMP - 1; // set valid_until to a time in the past
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EINVALID_ROOT_LEN)]
    public entry fun test_set_root__invalid_root_len(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let invalid_root = x"8ad6edb34398f637ca17e46b0b51ce50e18f56287aa0bf728ae3b5c4119c16";
        let set_root_args = default_set_root_args();
        set_root_args.root = invalid_root;
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EWRONG_CHAIN_ID)]
    public entry fun test_set_root__invalid_chain_id(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let set_root_args = default_set_root_args();
        set_root_args.chain_id = 111; // wrong chain id
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EWRONG_MULTISIG)]
    public entry fun test_set_root__invalid_multisig_addr(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let set_root_args = default_set_root_args();
        set_root_args.multisig = @0x12345; // wrong multisig address
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPENDING_OPS)]
    public entry fun test_set_root__pending_ops(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        // modify state to add pending ops
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
            root: ROOT,
            valid_until: VALID_UNTIL,
            op_count: 1
        };
        state.s_root_metadata.post_op_count = 2;

        let set_root_args = default_set_root_args();
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPROOF_CANNOT_BE_VERIFIED)]
    public entry fun test_set_root__override_previous_root(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        // modify state to add pending ops
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
            root: ROOT,
            valid_until: VALID_UNTIL,
            op_count: 0
        };
        state.s_root_metadata.post_op_count = 2;

        let set_root_args = default_set_root_args();
        set_root_args.override_previous_root = true;
        call_set_root(set_root_args);
        // since we only have one set of hardcoded signatures to work with, we dont bother generating a new root
        // and just expect this test to fail at proof validation, which happens after the pending ops check
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EWRONG_PRE_OP_COUNT)]
    public entry fun test_set_root__wrong_pre_op_count(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let set_root_args = default_set_root_args();
        set_root_args.pre_op_count = 1; // wrong pre op count, should equal op count (0)
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EWRONG_POST_OP_COUNT)]
    public entry fun test_set_root__wrong_post_op_count(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
            root: ROOT,
            valid_until: VALID_UNTIL,
            op_count: 1
        };
        state.s_root_metadata.post_op_count = 1;

        let set_root_args = default_set_root_args();
        set_root_args.pre_op_count = PRE_OP_COUNT + 1; // correct pre op count after state updates
        set_root_args.post_op_count = PRE_OP_COUNT; // post op count should be >= pre op count
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPROOF_CANNOT_BE_VERIFIED)]
    public entry fun test_set_root__empty_metadata_proof(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let set_root_args = default_set_root_args();
        set_root_args.metadata_proof = vector[]; // empty proof
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPROOF_CANNOT_BE_VERIFIED)]
    public entry fun test_set_root__metadata_not_consistent_with_proof(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let set_root_args = default_set_root_args();
        set_root_args.post_op_count = POST_OP_COUNT + 1; // post op count modified
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EMISSING_CONFIG)]
    public entry fun test_set_root__config_not_set(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let set_root_args = default_set_root_args();
        set_root_args.signatures = vector[]; // no signatures
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_ADDR_MUST_BE_INCREASING)]
    public entry fun test_set_root__out_of_order_signatures(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        let set_root_args = default_set_root_args();
        let sig0 = vector::borrow(&set_root_args.signatures, 0);
        let sig1 = vector::borrow(&set_root_args.signatures, 1);
        let sig2 = vector::borrow(&set_root_args.signatures, 2);
        set_root_args.signatures = vector[*sig0, *sig2, *sig1]; // shuffle signature order
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EINVALID_SIGNER)]
    public entry fun test_set_root__signature_from_invalid_signer(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        let set_root_args = default_set_root_args();
        let invalid_signer_sig = x"bb7f7e44b8d9c8f978c255c7efd6abb64e8fa9a33dcb6db2e2203d8aacd51dd471113ca6c8d1ed56bb0395f0bef0daf2fae6ef2cb5c86c57d148c7de473383461B";
        set_root_args.signatures = vector[invalid_signer_sig]; // add signature from invalid signer
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EINSUFFICIENT_SIGNERS)]
    public entry fun test_set_root__signer_quorum_not_met(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        let set_root_args = default_set_root_args();
        let signer1 = vector::borrow(&set_root_args.signatures, 0);
        set_root_args.signatures = vector[*signer1]; // only 1 signature, quorum is 2
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    public entry fun test_set_root__success(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        let set_root_args = default_set_root_args();

        call_set_root(set_root_args);

        let (root, valid_until) = get_root();
        assert!(root == ROOT, 0);
        assert!(valid_until == VALID_UNTIL, 1);
        let root_metadata = get_root_metadata();
        assert!(root_metadata.chain_id == (CHAIN_ID as u256), 2);
        assert!(root_metadata.multisig == @mcms, 3);
        assert!(root_metadata.pre_op_count == PRE_OP_COUNT, 4);
        assert!(root_metadata.post_op_count == POST_OP_COUNT, 5);
        assert!(root_metadata.override_previous_root == false, 6);
    }

    //// set_config tests ////
    
    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EUNATHORIZED)]
    public entry fun test_set_config__caller_is_not_owner(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let (not_owner, _) = account::create_resource_account(deployer, b"seed123");
        set_config(&not_owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
    }
    
    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EINVALID_NUM_SIGNERS)]
    public entry fun test_set_config__invalid_number_of_signers(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
         // empty signer addresses and groups
        let signer_addr = vector[];
        let signer_group = vector[];
        set_config(owner, signer_addr, signer_group, vector[], vector[], false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_ADDR_MUST_BE_INCREASING)]
    public entry fun test_set_config__signers_must_be_distinct(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        // same signer address twice
        let signer_addr = vector[ADDR1, ADDR2, ADDR2];
        set_config(owner, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_ADDR_MUST_BE_INCREASING)]
    public entry fun test_set_config__signers_must_be_increasing(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        // signer addresses out of order
        let signer_addr = vector[ADDR1, ADDR3, ADDR2];
        set_config(owner, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = ECMP_VECTORS_DIFF_LEN)]
    public entry fun test_set_config__invalid_signer_address(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        // signer address not 20 bytes
        let invalid_signer_addr = x"E37ca797F7fCCFbd9bb3bf8f812F19C3184df1";
        let signer_addr = vector[ADDR1, ADDR2, invalid_signer_addr];
        set_config(owner, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EOUT_OF_BOUNDS_GROUP)]
    public entry fun test_set_config__out_of_bounds_signer_group(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // signer group out of bounds
        let signer_groups = vector[1, 2, NUM_GROUPS];
        set_config(owner, signer_addr, signer_groups, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EOUT_OF_BOUNDS_GROUP_QUORUM)]
    public entry fun test_set_config__out_of_bounds_group_quorum(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group quorum out of bounds (greater than num signers)
        let group_quorums = right_pad_vec(vector[2, 1, 1, MAX_NUM_SIGNERS + 1], NUM_GROUPS);
        set_config(owner, signer_addr, SIGNER_GROUPS, group_quorums, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EGROUP_TREE_NOT_WELL_FORMED)]
    public entry fun test_set_config__root_is_not_its_own_parent(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group parent of root is group 1 (should be itself = group 0)
        let group_parents = right_pad_vec(vector[1], NUM_GROUPS);
        set_config(owner, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, group_parents, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EGROUP_TREE_NOT_WELL_FORMED)]
    public entry fun test_set_config__non_root_is_its_own_parent(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group parent of group 1 is itself (should be lower index group)
        let group_parents = right_pad_vec(vector[0, 1], NUM_GROUPS);
        set_config(owner, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, group_parents, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EGROUP_TREE_NOT_WELL_FORMED)]
    public entry fun test_set_config__group_parent_higher_index(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group parent of group 1 is group 2 (should be lower index group)
        let group_parents = right_pad_vec(vector[0, 2], NUM_GROUPS);
        set_config(owner, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, group_parents, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EOUT_OF_BOUNDS_GROUP_QUORUM)]
    public entry fun test_set_config__quorum_cannot_be_met(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group quorum of group 0 (root) is 4, which can never be met because there are only three child groups
        let group_quorum = right_pad_vec(vector[4, 1, 1, 1], NUM_GROUPS);
        set_config(owner, signer_addr, SIGNER_GROUPS, group_quorum, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_IN_DISABLED_GROUP)]
    public entry fun test_set_config__signer_in_disabled_group(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group 31 is disabled (quorum = 0) but signer 3 is in group 31
        let signer_groups = vector[1, 2, 31];
        set_config(owner, signer_addr, signer_groups, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_GROUPS_LEN_MISMATCH)]
    public entry fun test_set_config__signer_group_len_mismatch(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // len of signer groups does not match len of signers
        let signer_groups = vector[1, 2, 3, 3];
        set_config(owner, signer_addr, signer_groups, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    public entry fun test_set_config__success(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        let mcms_addr = setup(deployer, framework);

        // manually modify root state to check for modifications
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
            root: vector[1, 2, 3],
            valid_until: 9999,
            op_count: 5
        };
        state.s_root_metadata = RootMetadata {
            chain_id: 1,
            multisig: @0xabc,
            pre_op_count: 5,
            post_op_count: 5,
            override_previous_root: false
        };

        // test set config with clear_root=false
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        set_config(owner, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        let config = get_config();
        assert!(vector::length(&config.signers) == 3, 1);
        assert!(vector::borrow(&config.signers, 0).addr == ADDR1, 2);
        assert!(vector::borrow(&config.signers, 1).addr == ADDR2, 3);
        assert!(vector::borrow(&config.signers, 2).addr == ADDR3, 4);
        assert!(config.group_quorums == GROUP_QUORUMS, 5);
        assert!(config.group_parents == GROUP_PARENTS, 6);
        let (root, valid_until) = get_root();
        assert!(root == vector[1, 2, 3], 7);
        assert!(valid_until == 9999, 8);
        let metadata = get_root_metadata();
        assert!(metadata.chain_id == 1, 9);
        assert!(metadata.multisig == @0xabc, 10);
        assert!(metadata.pre_op_count == 5, 11);
        assert!(metadata.post_op_count == 5, 12);
        assert!(!metadata.override_previous_root, 13);

        // test set config with clear_root=true, change to 1-of-2 multisig with a nested 2-of-2 multisig
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        let signer_groups = vector[1, 3, 4];
        let group_quorums = right_pad_vec(vector[1, 1, 2, 1, 1], NUM_GROUPS);
        let group_parents = right_pad_vec(vector[0, 0, 0, 2, 2], NUM_GROUPS);
        set_config(owner, signer_addr, signer_groups, group_quorums, group_parents, true);
        let config = get_config();
        assert!(vector::length(&config.signers) == 3, 14);
        assert!(vector::borrow(&config.signers, 0).addr == ADDR1, 15);
        assert!(vector::borrow(&config.signers, 1).addr == ADDR2, 16);
        assert!(vector::borrow(&config.signers, 2).addr == ADDR3, 17);
        assert!(config.group_quorums == group_quorums, 18);
        assert!(config.group_parents == group_parents, 19);
        let (root, valid_until) = get_root();
        assert!(root == vector[], 20);
        assert!(valid_until == 0, 21);
        let metadata = get_root_metadata();
        assert!(metadata.chain_id == (CHAIN_ID as u256), 22);
        assert!(metadata.multisig == mcms_addr, 23);
        assert!(metadata.pre_op_count == 5, 24);
        assert!(metadata.post_op_count == 5, 25);
        assert!(metadata.override_previous_root, 26);
    }

    //// execute tests ////
    
    #[test(deployer = @mcms, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPOST_OP_COUNT_REACHED)]
    public entry fun test_execute__root_not_set(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        // since root not set, post op count is 0 which is not greater than current op count (also 0)
        let execute_args = default_execute_args();
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPOST_OP_COUNT_REACHED)]
    public entry fun test_execute__post_op_count_reached(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        call_set_root(default_set_root_args());
        // set current op count to post op count
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.s_expiring_root_and_op_count.op_count = state.s_root_metadata.post_op_count;
        let execute_args = default_execute_args();
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EWRONG_CHAIN_ID)]
    public entry fun test_execute__wrong_chain_id(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        call_set_root(default_set_root_args());
        let execute_args = default_execute_args();
        execute_args.chain_id = 111; // wrong chain id
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EWRONG_MULTISIG)]
    public entry fun test_execute__wrong_multisig_addr(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        call_set_root(default_set_root_args());
        let execute_args = default_execute_args();
        execute_args.multisig = @0x12345; // wrong multisig address
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EROOT_EXPIRED)]
    public entry fun test_execute__root_expired(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        call_set_root(default_set_root_args());
        // modify valid until state directly - set valid_until to a time in the past
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.s_expiring_root_and_op_count.valid_until = TIMESTAMP - 1;
        let execute_args = default_execute_args();
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EWRONG_NONCE)]
    public entry fun test_execute__wrong_nonce(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        call_set_root(default_set_root_args());
        let execute_args = default_execute_args();
        execute_args.nonce = execute_args.nonce + 1; // wrong nonce
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPROOF_CANNOT_BE_VERIFIED)]
    public entry fun test_execute__bad_op_proof(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        call_set_root(default_set_root_args());
        let execute_args = default_execute_args();
        execute_args.data = b"different data"; // modify op so proof verification should fail
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPROOF_CANNOT_BE_VERIFIED)]
    public entry fun test_execute__empty_proof(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        set_config(owner, vector[ADDR1, ADDR2, ADDR3], SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        call_set_root(default_set_root_args());
        let execute_args = default_execute_args();
        execute_args.proof = vector[]; // empty proof
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = EPROOF_CANNOT_BE_VERIFIED)]
    public entry fun test_execute__ops_executed_in_order(deployer: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        // modify state to add pending ops
        let state = borrow_global_mut<MCMState>(get_state_addr());
        state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
            root: ROOT,
            valid_until: VALID_UNTIL,
            op_count: 1
        };
        state.s_root_metadata.post_op_count = 2;

        let execute_args = default_execute_args();
        execute_args.nonce = OP1_NONCE + 1; // wrong nonce
        call_execute(execute_args);
    }

    // todo: test send values

    #[test(deployer = @mcms, owner = @owner, framework = @aptos_framework)]
    public entry fun test_ownable__transfer_ownership(deployer: &signer, owner: &signer, framework: &signer) acquires MCMState  {
        setup(deployer, framework);
        let new_owner = @0xdef;
        transfer_ownership(owner, new_owner);
        let updated_owner = owner();
        assert!(updated_owner == new_owner, 1);
    }


    //// utility function tests ////

    #[test]
    public entry fun test_utils__ecdsa_recover_evm_addr() {
        let eth_signed_message_hash = x"910cd291f5281f5bf25d8a83962f282b6c2bdf831f079dfcb84480f922abd2e1";
        let signature = x"45283a6239b1b559a910e97f79a52bab1605e8bd952c4b4e0720ed9b1e9e96712acab6f5f946bfa3dfa61f47705aff6e2f17f6ad83d484857bb119a06ba1f0e71C";
        let recovered_addr = ecdsa_recover_evm_addr(eth_signed_message_hash, signature);
        assert!(recovered_addr == x"16c9fACed8a1e3C6aEA2B654EEca5617eb900EFf", 1);
    }
    
    #[test]
    public entry fun test_utils__uint_to_bytes() {
        let large_u64: u64 = 1748317727; // hex = 0x6835361F
        let bytes = uint_to_bytes(large_u64);
        assert!(bytes == x"000000006835361f", 1);

        let u32_with_zero_bytes: u32 = 256; // hex = 0x0100
        let bytes_with_zero = uint_to_bytes(u32_with_zero_bytes);
        assert!(bytes_with_zero == x"00000100", 2);

        let u128_with_zero_bytes_2: u128 = 262144; // hex = 0x040000
        let bytes_with_zero_2 = uint_to_bytes(u128_with_zero_bytes_2);
        assert!(bytes_with_zero_2 == x"00000000000000000000000000040000", 3);

        let u256_num: u256 = 262144;
        let bytes_256 = uint_to_bytes(u256_num);
        assert!(bytes_256 == x"0000000000000000000000000000000000000000000000000000000000040000", 4);

        let max_u64: u64 = 18446744073709551615; // hex = 0xFFFFFFFFFFFFFFFF
        let bytes_max = uint_to_bytes(max_u64);
        assert!(bytes_max == x"ffffffffffffffff", 4);
    }

    #[test]
    public entry fun test_utils__compute_eth_message_hash() {
        let root = x"d5ef592d1ad183db43b4980d7ab7ee43a6f6a284988c3e3a23d38c07beb520c7";
        let valid_until = 1748317727;
        let hash = compute_eth_message_hash(root, valid_until);
        // test output computed from equivalent solidity function: ECDSA.toEthSignedMessageHash(keccak256(abi.encode(root, validUntil)));
        assert!(hash == x"032705bd71839baef725154f00f87ddcc1d95c4b5189c9fb5983f26ad6c95102", 1);
    }

    #[test]
    public entry fun test_utils__hash_metadata_leaf() {
        let metadata = RootMetadata {
            chain_id: 1,
            multisig: @0xabc,
            pre_op_count: 5,
            post_op_count: 5,
            override_previous_root: false
        };
        let hash = hash_metadata_leaf(metadata);
        // test output computed from equivalent solidity function: keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA, metadata))
        assert!(hash == x"ea6938e5cfa9b72197343db029e3146dec767d24f830eb750252076e439ccffa", 1);
    }

    #[test(deployer = @mcms, framework = @aptos_framework)]
    public entry fun test_utils__hash_op_leaf(deployer: &signer, framework: &signer) {
        setup(deployer, framework);
        let op = Op {
            chain_id: (CHAIN_ID as u256),
            multisig: @mcms,
            nonce: OP1_NONCE,
            data: OP1_DATA,
        };
        let hash = hash_op_leaf(op);
        // test output computed from equivalent solidity function: keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP, op))
        let expected_hash = vector::borrow(&LEAVES, 1);
        assert!(hash == *expected_hash, 0);
    }

    #[test]
    public entry fun test_utils__verify_merkle_proof() {
        let root = x"8ad6edb34398f637ca17e46b0b51ce50e18f56287aa0bf728ae3b5c4119c1600";
        let leaf_hash = x"03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760";
        let proof = vector[
            x"044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d",
            x"156d92046fd42325cec0997498d663ce343243a1ff530521e60d08407dbb0580",
            x"01b56d4f1b38f85ac9e8a826fb4d5210446e67a09594146d405f6f09f1a657f2",
            x"44164eac6b478d58bcff0081e764768c68e20c031ded38f87e823ceff0f76854",
            x"5b095d44d40824ca630f833c439211a0d8e63a0c2bb646b63b76de7cba9a35be",
            x"5a97fb1f239d0789fbd9ab71901b0c7c0c0ad8c1530df72ec0a21e72647e5e46"
        ];
        assert!(verify_merkle_proof(proof, root, leaf_hash), 1);
    }

    #[test]
    public entry fun test_utils__vector_u8_gt() {
        // a > b
        let a = vector[0x08, 0x0, 0x0, 0x0, 0x0];
        let b = vector[0x07, 0x4, 0x4, 0x3, 0x1];
        assert!(vector_u8_gt(a, b), 1);

        // c = d
        let c = vector[0x08, 0x0, 0x0, 0x0, 0x0];
        let d = vector[0x08, 0x0, 0x0, 0x0, 0x0];
        assert!(!vector_u8_gt(c, d), 2);

        // e < f
        let e = vector[0x08, 0x0, 0x0, 0x0, 0x0];
        let f = vector[0x08, 0x0, 0x0, 0x0, 0x1];
        assert!(!vector_u8_gt(e, f), 3);

        let sorted_addresses = vector[
            x"1D607AAD8aDd843bD3f87602b4D40DDaD477e748",
            x"2A704Fd168bf117eba7Da3E66aae0E932cc9221e",
            x"87191E05969b311242a7fF0a93d66Ac8B7B0bbB1",
            x"C211d666f61afCC311821c5f17E769F6e1515795",
            x"e0F4758dbD92E2499C95cb2c57bF605be032AF42"
        ];
        let prev_address = x"0000000000000000000000000000000000000001";
        vector::for_each(sorted_addresses, |addr| {
            assert!(vector_u8_gt(addr, prev_address), 7);
            prev_address = addr;
        });
    }

    #[test]
    public entry fun test_utils__right_pad_vec() {
        let input = vector[0x08, 0x0, 0x0, 0x0, 0x0];
        let padded = right_pad_vec(input, 10);
        assert!(padded == vector[8, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1);

        let input2 = vector[];
        let padded2 = right_pad_vec(input2, 5);
        assert!(padded2 == vector[0, 0, 0, 0, 0], 2);

        let input3 = vector[0x01, 0x2, 0x3, 0x4, 0x5];
        let padded3 = right_pad_vec(input3, 4);
        assert!(padded3 == vector[1, 2, 3, 4, 5], 3);
    }

    #[test]
    public entry fun test_utils__left_pad_vec() {
        let input = vector[0x08, 0x0, 0x0, 0x0, 0x0];
        let padded = left_pad_vec(input, 10);
        assert!(padded == vector[0, 0, 0, 0, 0, 8, 0, 0, 0, 0], 1);

        let input2 = vector[];
        let padded2 = left_pad_vec(input2, 5);
        assert!(padded2 == vector[0, 0, 0, 0, 0], 2);

        let input3 = vector[0x01, 0x2, 0x3, 0x4, 0x5];
        let padded3 = left_pad_vec(input3, 4);
        assert!(padded3 == vector[1, 2, 3, 4, 5], 3);
    }
}
