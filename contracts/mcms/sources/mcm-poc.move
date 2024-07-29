module mcms::multisig {
    use std::error;
    use std::signer;
    use std::vector;
    use std::simple_map::{SimpleMap,Self};
    use std::resource_account;
    use std::aptos_hash::keccak256;
    use aptos_framework::multisig_account;
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::timestamp;

    // MCM Structs

    struct RootMetadata has key, store, drop {
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

    struct MCMState has key, store, drop {
        seen_signed_hashes: SimpleMap<vector<u8>, bool>,
        root: vector<u8>,
        valid_until: u64,
        op_count: u64,
        metadata: RootMetadata,
        addr: address,
		signer_cap: account::SignerCapability	
	}

    // Error Codes
    const ENO_MULTISIG: u64 = 1;
    const EALREADY_SEEN_HASH: u64 = 2;
    const EPOST_OP_COUNT_REACHED: u64 = 3;
    const EWRONG_CHAIN_ID: u64 = 4;
    const EWRONG_MULTISIG: u64 = 5;
    const EROOT_EXPIRED: u64 = 6;
    const EWRONG_NONCE: u64 = 7;

    // TODO: replace resource acc addr params with fixed address alias to be defined at deployment in Move.toml

    // MCM Getters 

    // function getConfig() public view returns (Config memory) {
    //     return s_config;
    // }
    public fun get_config() {} // todo

    // function getOpCount() public view returns (uint40) {
    //     return s_expiringRootAndOpCount.opCount;
    // }
    public fun get_op_count() {} // todo

    // function getRoot() public view returns (bytes32 root, uint32 validUntil) {
    //     ExpiringRootAndOpCount memory currentRootAndOpCount = s_expiringRootAndOpCount;
    //     return (currentRootAndOpCount.root, currentRootAndOpCount.validUntil);
    // }
    public fun get_root() {} // todo

    // function getRootMetadata() public view returns (RootMetadata memory) {
    //     return s_rootMetadata;
    // }
    public fun get_root_metadata() {} // todo
    
    // Getters to help manage the wrapped multisig account

    #[view]
    public fun get_multisig_addr(resource_acc_addr: address): address acquires MCMState {
        assert!(exists<MCMState>(resource_acc_addr), error::not_found(ENO_MULTISIG));
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
        assert!(simple_map::contains_key(&mut state.seen_signed_hashes, &signed_hash) == false, error::invalid_state(EALREADY_SEEN_HASH));

        // verify ECDSA signatures on (root, validUntil) and ensure that the root group is successful

        // verify validUntil against current timestamp

        // verify metadata proof, chain id, multisig addr, op counts

        // save details to contract state     
        simple_map::add(&mut state.seen_signed_hashes, signed_hash, true);
        state.root = root;
        state.valid_until = valid_until;
        state.metadata = RootMetadata { 
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
        assert!(state.metadata.post_op_count <= state.op_count, error::invalid_state(EPOST_OP_COUNT_REACHED));

        assert!(chain_id == (chain_id::get() as u256), error::invalid_state(EWRONG_CHAIN_ID));

        assert!(timestamp::now_microseconds() > state.valid_until, error::invalid_state(EROOT_EXPIRED));

        assert!(nonce == state.op_count, error::invalid_state(EWRONG_NONCE));

        // verify op exists in merkle tree

        // increment op_count
        state.op_count = state.op_count + 1;

        // create transaction on multisig account
        // todo: investigate if `to` and `value` params are encoded in the `data` payload
        // todo: investigate if `value` is relevant for Aptos at all
        let multisig_addr = get_multisig_addr(resource_acc_addr);
        let multisig_signer = multisig_signer(resource_acc_addr);
        multisig_account::create_transaction(&multisig_signer, multisig_addr, data);
    }

    public entry fun set_config(
        _resource_account: &signer,
        _owner_address: address,
        _signer_addresses: vector<vector<u8>>,
        _signer_groups: vector<u8>,
        _group_quorums: vector<u8>,
        _group_parents: vector<u8>,
        _clear_root: bool
    ) {
        // check access control

        // set MCM config
    }

    // Internal functions

    fun init_multisig_internal(resource_account: &signer, signer_cap: account::SignerCapability) {
        let resource_account_addr = signer::address_of(resource_account);
        let multisig_addr = multisig_account::get_next_multisig_account_address(resource_account_addr);

        // create multisig account with resource account as sole owner and quorum of 1
        multisig_account::create(resource_account, 1, vector[], vector[]);

        // initialize storage and save multisig address and signer cap
        move_to(resource_account, MCMState { 
            seen_signed_hashes: simple_map::new(),
            root: vector[],
            valid_until: 0,
            op_count: 0,
            metadata: RootMetadata { chain_id: 0, multisig: multisig_addr, pre_op_count: 0, post_op_count: 0, override_previous_root: false },
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
        assert!(exists<MCMState>(resource_acc_addr), error::not_found(ENO_MULTISIG));
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

    // TESTS //

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

    #[test_only]
    fun setup(account: &signer, framework: &signer) {
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
    }

    #[test(account = @0xabc, framework = @aptos_framework)]
    public entry fun test_e2e(account: &signer, framework: &signer) acquires MCMState  {
        setup(account, framework);
        let owner_addr = signer::address_of(account);

        // create resource account
        let (resource, signer_cap) = account::create_resource_account(account, SEED);
        let resource_acc_addr = signer::address_of(&resource);

        // init multisig using internal fn as we cant use retrieve_resource_account_cap in a test (error: ECONTAINER_NOT_PUBLISHED)
        init_multisig_internal(&resource, signer_cap);
        
        // set config
        set_config(&resource, owner_addr, vector[], vector[], vector[], vector[], false);
        
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
}
