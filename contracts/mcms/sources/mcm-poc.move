module mcms::multisig {
    use std::error;
    use std::signer;
    use std::vector;
    use std::event;
    use std::simple_map::{SimpleMap,Self};
    use std::resource_account;
    use std::aptos_hash::keccak256;
    use aptos_framework::multisig_account;
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::timestamp;

    // MCM Consts
    const NUM_GROUPS: u8 = 32;
    const MAX_NUM_SIGNERS: u8 = 200;

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

    // MCM Structs
    struct RootMetadata has key, store, copy, drop {
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool
    }

    struct Signature has store, drop {
        v: u8,
        r: vector<u8>,
        s: vector<u8>
    }

    struct Op has store, drop {
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        value: u256,
        data: vector<u8>
    }

    struct Signer has key, store, copy, drop {
        addr: vector<u8>,
        index: u8, // index of signer in s_config.signers
        group: u8 // 0 <= group < NUM_GROUPS. Each signer can only be in one group.
    }

    struct Config has key, store, copy, drop {
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

    struct ExpiringRootAndOpCount has key, store, drop {
        root: vector<u8>,
        valid_until: u64,
        op_count: u64
    }

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
		signer_cap: account::SignerCapability	
	}

    #[event]
    struct ConfigSet has drop, store {
        config: Config,
        is_root_cleared: bool
    }


    // TODO: replace resource acc and mcm addr params with fixed address alias to be defined at deployment in Move.toml

    // MCM Getters 

    #[view]
    public fun get_config(mcm_address: address): Config acquires MCMState {
        borrow_global<MCMState>(mcm_address).s_config
    }

    #[view]
    public fun get_op_count(mcm_address: address): u64 acquires MCMState {
        borrow_global<MCMState>(mcm_address).s_expiring_root_and_op_count.op_count
    }

    #[view]
    public fun get_root(mcm_address: address): (vector<u8>, u64) acquires MCMState {
        let state = borrow_global<MCMState>(mcm_address);
        (state.s_expiring_root_and_op_count.root, state.s_expiring_root_and_op_count.valid_until)
    }

    #[view]
    public fun get_root_metadata(mcm_address: address): RootMetadata acquires MCMState {
        borrow_global<MCMState>(mcm_address).s_root_metadata
    }
    
    // Getters to help manage the wrapped extended multisig account

    #[view]
    public fun get_multisig_addr(resource_acc_addr: address): address acquires MCMState {
        assert!(exists<MCMState>(resource_acc_addr), ENO_MULTISIG);
        borrow_global<MCMState>(resource_acc_addr).addr
    }

    #[view]
    public fun get_pending_transactions(resource_acc_addr: address): vector<multisig_account::MultisigTransaction> acquires MCMState {
        multisig_account::get_pending_transactions(get_multisig_addr(resource_acc_addr))
    }

    #[view]
    public fun get_transaction(resource_acc_addr: address, sequence_number: u64): multisig_account::MultisigTransaction acquires MCMState {
        multisig_account::get_transaction(get_multisig_addr(resource_acc_addr), sequence_number)
    }

    #[view]
    public fun get_last_resolved_sequence_number(resource_acc_addr: address): u64 acquires MCMState {
        multisig_account::last_resolved_sequence_number(get_multisig_addr(resource_acc_addr))
    }

    #[view]
    public fun get_next_sequence_number(resource_acc_addr: address): u64 acquires MCMState {
        multisig_account::next_sequence_number(get_multisig_addr(resource_acc_addr))
    }

    // MCM Functions

    public entry fun init(resource_account: &signer, owner_address: address) {
        // todo: this assumes that the passed in owner address owns the resource account.
        let signer_cap = resource_account::retrieve_resource_account_cap(resource_account, owner_address);
        init_multisig_internal(resource_account, signer_cap);
    }

    public entry fun set_root(
        resource_acc_addr: address,
        root: vector<u8>,
        valid_until: u64,
        chain_id: u256,
        multisig: address,
        pre_op_count: u64,
        post_op_count: u64,
        override_previous_root: bool,
        _metadata_proof: vector<vector<u8>>,
        _signatures: vector<vector<u8>>
    ) acquires MCMState {
        let state = borrow_global_mut<MCMState>(resource_acc_addr);
        let signed_hash = compute_eth_message_hash(root, valid_until);

        // check if hash has been seen already
        assert!(simple_map::contains_key(&mut state.s_seen_signed_hashes, &signed_hash) == false, EALREADY_SEEN_HASH);

        // verify ECDSA signatures on (root, valid_until) and ensure that the root group is successful

        // verify valid_until against current timestamp
        assert!(timestamp::now_microseconds() > valid_until, EVALID_UNTIL_EXPIRED);


        // verify metadata proof, chain id, multisig addr, op counts

        // save details to contract state     
        simple_map::add(&mut state.s_seen_signed_hashes, signed_hash, true);
        state.s_expiring_root_and_op_count = ExpiringRootAndOpCount {
            root,
            valid_until,
            op_count: pre_op_count
        };
        state.s_root_metadata = RootMetadata { 
            chain_id,
            multisig,
            pre_op_count,
            post_op_count,
            override_previous_root
        };

    }

    // note: unlike MCM on EVM chains, this function does not actually execute the transaction,
    // but rather creates the transaction on the multisig account to be executed in a separate tx
    public entry fun execute(
        resource_acc_addr: address,
        chain_id: u256,
        nonce: u64,
        _to: address,
        _value: u256,
        data: vector<u8>,
        _proof: vector<vector<u8>>
    ) acquires MCMState {
        let state = borrow_global_mut<MCMState>(resource_acc_addr);

        // op validations
        assert!(state.s_root_metadata.post_op_count <= state.s_expiring_root_and_op_count.op_count, EPOST_OP_COUNT_REACHED);

        assert!(chain_id == (chain_id::get() as u256), EWRONG_CHAIN_ID);

        assert!(timestamp::now_microseconds() > state.s_expiring_root_and_op_count.valid_until, EROOT_EXPIRED);

        assert!(nonce == state.s_expiring_root_and_op_count.op_count, EWRONG_NONCE);

        // verify op exists in merkle tree

        // increment op_count
        state.s_expiring_root_and_op_count.op_count = state.s_expiring_root_and_op_count.op_count + 1;

        // create transaction on multisig account
        // todo: investigate if `to` and `value` params are encoded in the `data` payload
        // todo: investigate if `value` is relevant for Aptos at all
        let multisig_addr = get_multisig_addr(resource_acc_addr);
        let multisig_signer = multisig_signer(resource_acc_addr);
        multisig_account::create_transaction(&multisig_signer, multisig_addr, data);
    }

    public entry fun set_config(
        resource_account: &signer,
        resource_acc_addr: address,
        signer_addresses: vector<vector<u8>>,
        signer_groups: vector<u8>,
        group_quorums: vector<u8>,
        group_parents: vector<u8>,
        clear_root: bool
    ) acquires MCMState {
        // todo: check access control

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
        let state = borrow_global_mut<MCMState>(resource_acc_addr); // todo: can get from resource_account?
        let old_signers = state.s_config.signers;
        vector::for_each(old_signers, |signer| {
            simple_map::remove(&mut state.s_signers, &signer.addr);
            vector::pop_back(&mut state.s_config.signers);
        });
        assert!(vector::length(&state.s_config.signers) == 0, ERR);

        // save group quorums and parents to state
        state.s_config.group_quorums = group_quorums;
        state.s_config.group_parents = group_parents;

        // check signer addresses are in increasing order and save signers to state
        // evm zero address (20 bytes of 0) is the smallest address possible
        let prev_signer_addr: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let i = 0;
        while (i < vector::length(&signer_addresses)) {
            let signer_addr = vector::borrow(&signer_addresses, (i as u64));
            // this has a nice side effect of checking that each signer address is 20 bytes
            // and all signers are distinct
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
                multisig: @chainlink,
                pre_op_count: op_count,
                post_op_count: op_count,
                override_previous_root: true
            };
        };

        event::emit(ConfigSet { config: state.s_config, is_root_cleared: clear_root });
    }

    // Internal functions

    fun init_multisig_internal(resource_account: &signer, signer_cap: account::SignerCapability) {
        let resource_account_addr = signer::address_of(resource_account);
        let multisig_addr = multisig_account::get_next_multisig_account_address(resource_account_addr);

        // create multisig account with resource account as sole owner and quorum of 1
        multisig_account::create(resource_account, 1, vector[], vector[]);

        // initialize storage and save multisig address and signer cap
        move_to(resource_account, MCMState { 
            s_signers: simple_map::new(),
            s_config: Config { signers: vector[], group_quorums: vector[], group_parents: vector[] },
            s_seen_signed_hashes: simple_map::new(),
            s_expiring_root_and_op_count: ExpiringRootAndOpCount { root: vector[], valid_until: 0, op_count: 0 },
            s_root_metadata: RootMetadata { chain_id: 0, multisig: multisig_addr, pre_op_count: 0, post_op_count: 0, override_previous_root: false },
            addr: multisig_addr,
            signer_cap
        });
    }

    fun compute_eth_message_hash(root: vector<u8>, valid_until: u64): vector<u8> {
        // abi.encode(root, valid_until)
        let valid_until_bytes = u64_to_bytes(valid_until);
        let len_valid_until = vector::length(&valid_until_bytes);
        let bytes_to_pad = 32 - len_valid_until;
        let padded_valid_until: vector<u8> = vector[];
        let i = 0;
        while (i < bytes_to_pad) {
            vector::push_back(&mut padded_valid_until, 0);
            i = i + 1;
        };
        vector::append<u8>(&mut padded_valid_until, valid_until_bytes);
        let abi_encoded_params = &mut root;
        vector::append(abi_encoded_params, padded_valid_until);

        // keccak256(abi_encoded_params)
        let hashed_encoded_params = keccak256(*abi_encoded_params);

        // ECDSA.toEthSignedMessageHash()
        let eth_msg_prefix = b"\x19Ethereum Signed Message:\n32";
        let hash = &mut eth_msg_prefix;
        vector::append(hash, hashed_encoded_params);
        keccak256(*hash)
    }

    // retrieve signer for multisig account - should be protected with appropriate guards
    fun multisig_signer(resource_acc_addr: address): signer acquires MCMState {
        assert!(exists<MCMState>(resource_acc_addr), ENO_MULTISIG);
        account::create_signer_with_capability(&borrow_global<MCMState>(resource_acc_addr).signer_cap)
    }

    // helper function to convert u64 to bytes
    // note: does not remove leading zero bytes, however this is fine as we are using this in the
    // context of compute_eth_message_hash which left zero-pads valid_until to 32 bytes anyway.
    fun u64_to_bytes(int: u64): vector<u8> {
        let bcs_bytes = std::bcs::to_bytes(&int);
        vector::reverse(&mut bcs_bytes);
        bcs_bytes
    }

    // helper function to right pad a vector<u8> with zero bytes to a specified length
    // this function returns the input if the input length is already equal to or greater than num_bytes
    fun right_pad_vec(input: vector<u8>, num_bytes: u8): vector<u8> {
        let len = vector::length(&input);
        if (len >= (num_bytes as u64)) {
            return input;
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

    // helper function to compare two vector<u8> values. expects both vectors to be of equal length.
    // returns true if a > b, false otherwise
    fun vector_u8_gt(a: vector<u8>, b: vector<u8>): bool {
        let len_a = vector::length(&a);
        let len_b = vector::length(&b);
        assert!(len_a == len_b, ECMP_VECTORS_DIFF_LEN);

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
                return true;
            } else if (byte_a < byte_b) {
                return false;
            };
        };

        // vectors are equal, a == b
        false
    }

    //// TESTS ////

    #[test_only]
    use aptos_framework::coin;
    #[test_only]
    use aptos_framework::aptos_coin;

    #[test_only]
    const PAYLOAD: vector<u8> = vector[1, 2, 3]; // test tx payload, not actually executed
    #[test_only]
    const SEED: vector<u8> = b"test";
    #[test_only]
    const CHAIN_ID: u8 = 123;
    #[test_only]
    const TIMESTAMP: u64 = 1000;

    // EVM addresses 1 - 3 in ascending order
    #[test_only]
    const ADDR1: vector<u8> = x"311C1CD570527373481D1Dce1dEcb7F23E93C86C";
    #[test_only]
    const ADDR2: vector<u8>  = x"37f8f76e04fbF5cc93b7f54cEE4Ee062073A9808";
    #[test_only]
    const ADDR3: vector<u8>  = x"E37ca797F7fCCFbd9bb3bf8f812F19C3184df193";

    // test config: 2-of-3 multisig
    #[test_only]
    const SIGNER_GROUPS: vector<u8> = vector[1, 2, 3];
    #[test_only]
    const GROUP_QUORUMS: vector<u8> = vector[2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    #[test_only]
    const GROUP_PARENTS: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test_only]
    fun setup(account: &signer, framework: &signer): (signer, address) {
        // setup aptos coin for test
        let (burn, mint) = aptos_coin::initialize_for_test(framework);
        coin::destroy_mint_cap(mint);
        coin::destroy_burn_cap(burn);
        // setup account for test
        let addr = signer::address_of(account);
        aptos_framework::account::create_account_for_test(addr);
        // setup test components
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);
        chain_id::initialize_for_test(framework, CHAIN_ID);

        // create resource account
        let (resource, signer_cap) = account::create_resource_account(account, SEED);

        // init multisig using internal fn as we cant use retrieve_resource_account_cap in a test (error: ECONTAINER_NOT_PUBLISHED)
        init_multisig_internal(&resource, signer_cap);

        // returns resource account and its address
        let resource_acc_addr = signer::address_of(&resource);
        (resource, resource_acc_addr)
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    public entry fun test_e2e(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let owner_addr = signer::address_of(account);
        
        // set config
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        set_config(&resource, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        
        // set root
        let root = vector[1, 2, 3];
        let valid_until = TIMESTAMP + 10;
        set_root(resource_acc_addr, root, valid_until, (CHAIN_ID as u256), owner_addr, 0, 0, false, vector[], vector[]);

        // check pending txs on the wrapped multisig
        let pending_txs = get_pending_transactions(resource_acc_addr);
        assert!(vector::length(&pending_txs) == 0, 0);

        // execute op (creates transaction on multisig)
        execute(resource_acc_addr, (CHAIN_ID as u256), 0, owner_addr, 0, PAYLOAD, vector[]);

        // check pending txs on the wrapped multisig
        let pending_txs = get_pending_transactions(resource_acc_addr);
        assert!(vector::length(&pending_txs) == 1, 1);

        // check tx can be executed
        let multisig_address = get_multisig_addr(resource_acc_addr);
        assert!(multisig_account::can_be_executed(multisig_address, 1), 2);
    }

    //// set_config tests ////
    
    // todo: test revert on non owner caller
    
    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = EINVALID_NUM_SIGNERS)]
    public entry fun test_set_config_invalid_number_of_signers(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
         // empty signer addresses and groups
        let signer_addr = vector[];
        let signer_group = vector[];
        set_config(account, resource_acc_addr, signer_addr, signer_group, vector[], vector[], false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_ADDR_MUST_BE_INCREASING)]
    public entry fun test_set_config_signers_must_be_distinct(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        // same signer address twice
        let signer_addr = vector[ADDR1, ADDR2, ADDR2];
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_ADDR_MUST_BE_INCREASING)]
    public entry fun test_set_config_signers_must_be_increasing(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        // signer addresses out of order
        let signer_addr = vector[ADDR1, ADDR3, ADDR2];
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = ECMP_VECTORS_DIFF_LEN)]
    public entry fun test_set_config_invalid_signer_address(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        // signer address not 20 bytes
        let invalid_signer_addr = x"E37ca797F7fCCFbd9bb3bf8f812F19C3184df1";
        let signer_addr = vector[ADDR1, ADDR2, invalid_signer_addr];
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = EOUT_OF_BOUNDS_GROUP)]
    public entry fun test_set_config_out_of_bounds_signer_group(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // signer group out of bounds
        let signer_groups = vector[1, 2, NUM_GROUPS];
        set_config(account, resource_acc_addr, signer_addr, signer_groups, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = EOUT_OF_BOUNDS_GROUP_QUORUM)]
    public entry fun test_set_config_out_of_bounds_group_quorum(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group quorum out of bounds (greater than num signers)
        let group_quorums = right_pad_vec(vector[2, 1, 1, MAX_NUM_SIGNERS + 1], NUM_GROUPS);
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, group_quorums, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = EGROUP_TREE_NOT_WELL_FORMED)]
    public entry fun test_set_config_root_is_not_its_own_parent(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group parent of root is group 1 (should be itself = group 0)
        let group_parents = right_pad_vec(vector[1], NUM_GROUPS);
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, group_parents, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = EGROUP_TREE_NOT_WELL_FORMED)]
    public entry fun test_set_config_non_root_is_its_own_parent(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group parent of group 1 is itself (should be lower index group)
        let group_parents = right_pad_vec(vector[0, 1], NUM_GROUPS);
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, group_parents, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = EGROUP_TREE_NOT_WELL_FORMED)]
    public entry fun test_set_config_group_parent_higher_index(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group parent of group 1 is group 2 (should be lower index group)
        let group_parents = right_pad_vec(vector[0, 2], NUM_GROUPS);
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, group_parents, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = EOUT_OF_BOUNDS_GROUP_QUORUM)]
    public entry fun test_set_config_quorum_cannot_be_met(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group quorum of group 0 (root) is 4, which can never be met because there are only three child groups
        let group_quorum = right_pad_vec(vector[4, 1, 1, 1], NUM_GROUPS);
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, group_quorum, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_IN_DISABLED_GROUP)]
    public entry fun test_set_config_signer_in_disabled_group(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // group 31 is disabled (quorum = 0) but signer 3 is in group 31
        let signer_groups = vector[1, 2, 31];
        set_config(account, resource_acc_addr, signer_addr, signer_groups, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    #[expected_failure(abort_code = ESIGNER_GROUPS_LEN_MISMATCH)]
    public entry fun test_set_config_signer_group_len_mismatch(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);
        let signer_addr = vector[ADDR1, ADDR2, ADDR3];
        // len of signer groups does not match len of signers
        let signer_groups = vector[1, 2, 3, 3];
        set_config(account, resource_acc_addr, signer_addr, signer_groups, GROUP_QUORUMS, GROUP_PARENTS, false);
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    public entry fun test_set_config_success(account: &signer, framework: &signer) acquires MCMState  {
        let (resource, resource_acc_addr) = setup(account, framework);

        // manually modify root state to check for modifications
        let state = borrow_global_mut<MCMState>(resource_acc_addr);
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
        set_config(account, resource_acc_addr, signer_addr, SIGNER_GROUPS, GROUP_QUORUMS, GROUP_PARENTS, false);
        let config = get_config(resource_acc_addr);
        assert!(vector::length(&config.signers) == 3, 1);
        assert!(vector::borrow(&config.signers, 0).addr == ADDR1, 2);
        assert!(vector::borrow(&config.signers, 1).addr == ADDR2, 3);
        assert!(vector::borrow(&config.signers, 2).addr == ADDR3, 4);
        assert!(config.group_quorums == GROUP_QUORUMS, 5);
        assert!(config.group_parents == GROUP_PARENTS, 6);
        let (root, valid_until) = get_root(resource_acc_addr);
        assert!(root == vector[1, 2, 3], 7);
        assert!(valid_until == 9999, 8);
        let metadata = get_root_metadata(resource_acc_addr);
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
        set_config(account, resource_acc_addr, signer_addr, signer_groups, group_quorums, group_parents, true);
        let config = get_config(resource_acc_addr);
        assert!(vector::length(&config.signers) == 3, 14);
        assert!(vector::borrow(&config.signers, 0).addr == ADDR1, 15);
        assert!(vector::borrow(&config.signers, 1).addr == ADDR2, 16);
        assert!(vector::borrow(&config.signers, 2).addr == ADDR3, 17);
        assert!(config.group_quorums == group_quorums, 18);
        assert!(config.group_parents == group_parents, 19);
        let (root, valid_until) = get_root(resource_acc_addr);
        assert!(root == vector[], 20);
        assert!(valid_until == 0, 21);
        let metadata = get_root_metadata(resource_acc_addr);
        assert!(metadata.chain_id == (CHAIN_ID as u256), 22);
        assert!(metadata.multisig == @chainlink, 23);
        assert!(metadata.pre_op_count == 5, 24);
        assert!(metadata.post_op_count == 5, 25);
        assert!(metadata.override_previous_root, 26);
    }

    //// utility function tests ////

    #[test]
    public entry fun test_u64_to_bytes() {
        let large_num: u64 = 1748317727; // hex = 0x6835361F
        let bytes = u64_to_bytes(large_num);
        assert!(bytes == x"000000006835361f", 1);

        let num_with_zero_bytes: u64 = 256; // hex = 0x0100
        let bytes_with_zero = u64_to_bytes(num_with_zero_bytes);
        assert!(bytes_with_zero == x"0000000000000100", 2);

        let num_with_zero_bytes_2: u64 = 262144; // hex = 0x040000
        let bytes_with_zero_2 = u64_to_bytes(num_with_zero_bytes_2);
        assert!(bytes_with_zero_2 == x"0000000000040000", 3);

        let max_u64: u64 = 18446744073709551615; // hex = 0xFFFFFFFFFFFFFFFF
        let bytes_max = u64_to_bytes(max_u64);
        assert!(bytes_max == x"ffffffffffffffff", 4);
    }

    #[test]
    public entry fun test_compute_eth_message_hash() {
        let root = x"d5ef592d1ad183db43b4980d7ab7ee43a6f6a284988c3e3a23d38c07beb520c7";
        let valid_until = 1748317727;
        let hash = compute_eth_message_hash(root, valid_until);
        // test output computed from equivalent solidity function: ECDSA.toEthSignedMessageHash(keccak256(abi.encode(root, validUntil)));
        assert!(hash == x"032705bd71839baef725154f00f87ddcc1d95c4b5189c9fb5983f26ad6c95102", 1);
    }

    #[test]
    public entry fun test_vector_u8_gt() {
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

        
        assert!(vector_u8_gt(ADDR2, ADDR1), 4);
        assert!(vector_u8_gt(ADDR3, ADDR2), 5);
        assert!(vector_u8_gt(ADDR3, ADDR1), 6);
    }

    #[test]
    public entry fun test_right_pad_vec() {
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
}
