#[test_only]
module mcms::mcms_tests {

    use std::vector;
    use std::string;
    use std::signer;
    use std::string::String;
    use aptos_framework::aptos_coin;
    use aptos_framework::chain_id;
    use aptos_framework::coin;
    use aptos_framework::timestamp;
    use mcms::mcms;
    use mcms::mcms_account;
    use std::object;
    use std::simple_map;
    use aptos_framework::account;
    use std::bcs;
    use mcms::params::{Self};
    use mcms::object_code_util;
    use mcms::mcms_registry;
    use std::code::{PackageRegistry};

    // keccak256("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP_APTOS")
    const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP: vector<u8> = x"e5a6d1256b00d7ec22512b6b60a3f4d75c559745d2dbf309f77b8b756caabe14";

    const CHAIN_ID: u256 = 4;
    const TIMESTAMP: u64 = 1744315405;

    const MIN_DELAY: u64 = 3600; // 1 hour delay
    const TEST_TARGET_ADDRESS: address = @0xabc;
    const TEST_SALT: vector<u8> = x"1234567890abcdef";
    const TEST_PREDECESSOR: vector<u8> = x"";

    // Proposer signers from the logs (already in ascending order)
    const PROPOSER_ADDR1: vector<u8> = x"5916431f0ea809587757df994233861e1271be55";
    const PROPOSER_ADDR2: vector<u8> = x"8803c3ed076e57d51e28301933418094bd961cc5";
    const PROPOSER_ADDR3: vector<u8> = x"8950e6c6832c9b0591801418684d27b2853b2c74";

    // test config: 2-of-3 multisig
    const SIGNER_GROUPS: vector<u8> = vector[0, 0, 0];

    const GROUP_QUORUMS: vector<u8> = vector[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    const GROUP_PARENTS: vector<u8> = vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    const ROOT: vector<u8> = x"f7a8b0f28b2ae826313604377ecd0dd07dd4107e0777db5d251560aa2dbf760d";
    const POST_OP_COUNT: u64 = 4;

    const METADATA_PROOF: vector<vector<u8>> = vector[
        x"66cf50cb9a50c740313fd0f889b676af60d35ef700711d94df6eeff3f1ba66c2",
        x"951f1094081a858642cc6635f0885317828a7fddddd00668391c50f1e9e1bb66",
        x"597116801e22b18150f2abc4ca2ecd63e147bb67e24e4b5f900d49b909e1919f"
    ];

    const OP1_PROOF: vector<vector<u8>> = vector[
        x"a619565e90c1c564293b59b344ed0e12ed06eafb3c45b70baf6fdf299a046297", // metadata hash
        x"951f1094081a858642cc6635f0885317828a7fddddd00668391c50f1e9e1bb66", // sibling at level 1
        x"597116801e22b18150f2abc4ca2ecd63e147bb67e24e4b5f900d49b909e1919f" // sibling at level 2
    ];

    // The OPs contained are
    // {
    // 			Target:      mcmsAccount,
    // 			ModuleName:  "mcms_account",
    // 			Function:    "accept_ownership",
    // 			Data:        []byte{},
    // 			Delay:       1,
    // 			Predecessor: []byte{},
    // 			Salt:        []byte{},
    // 		},
    // 		{
    // 			Target:      mcmsAccount,
    // 			ModuleName:  "mcms_deployer",
    // 			Function:    "stage_code_chunk_and_publish_to_object",
    // 			Data:        stageCodeChunkAndPublishToAccountBytes,
    // 			Delay:       1,
    // 			Predecessor: []byte{},
    // 			Salt:        []byte{},
    // 		},
    // 		{
    // 			Target:      userModuleAccount,
    // 			ModuleName:  "mcms_user",
    // 			Function:    "function_one",
    // 			Data:        functionOneParamBytes,
    // 			Delay:       1,
    // 			Predecessor: []byte{},
    // 			Salt:        []byte{},
    // 		},
    // 		{
    // 			Target:      userModuleAccount,
    // 			ModuleName:  "mcms_user",
    // 			Function:    "function_two",
    // 			Data:        functionTwoParamBytes,
    // 			Delay:       1,
    // 			Predecessor: []byte{},
    // 			Salt:        []byte{},
    // 		},
    const LEAVES: vector<vector<u8>> = vector[
        x"a619565e90c1c564293b59b344ed0e12ed06eafb3c45b70baf6fdf299a046297", // metadata hash
        x"66cf50cb9a50c740313fd0f889b676af60d35ef700711d94df6eeff3f1ba66c2", // op1 hash
        x"2feec0e3a232c5c847874246203e62c43db473fe85245095122e166be9114e13", // op2 hash
        x"411a4726f8a920fc0a814bd9897a06f3dd0f1c799a047deaa6469f105f5a6705", // op3 hash
        x"cb4dffef33843b197cd33346d3339d8432b14789504167c63fb9f74a73baaea5" // op4 hash
    ];

    const VALID_UNTIL: u64 = 1744315405;
    const PRE_OP_COUNT: u64 = 0;

    const SIGNATURES: vector<vector<u8>> = vector[
        x"72398e2f325e707217fa8108a08c126f49f4144c30c7e93896d139c9f1d9468c30424b060c19fa5c7820a17b57badb19375207c787878533834618688a4780581c",
        x"9bb8ba839f9152cdc61556fcc70b0ebcb4d442654263a3d1c323e1eed85ebc6016e87c8e59f12d850b9d6b789ccafd93f19dcf65eb6fc75fd4351d5970214c1d1c",
        x"225739c80de11d50f3dca8fbb8288881abad17439690abd8eee32d48ff2f6dd204c48aff2fac4dfe8ce7176fd12d2633d7892bfb3d3f3cfeb00352773fe55c8c1b"
    ];

    const OP1_NONCE: u64 = 0;
    const OP1_DATA: vector<u8> = x"01a969156fce9a4f08bcdc07b90f338efc630bff8dfa8340500cb6414aca762a4e010c6d636d735f6163636f756e7401106163636570745f6f776e6572736869700100200000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test_only]
    fun setup(deployer: &signer, owner: &signer, framework: &signer): address {
        // setup aptos coin for test
        let (burn, mint) = aptos_coin::initialize_for_test(framework);
        coin::destroy_mint_cap(mint);
        coin::destroy_burn_cap(burn);
        // setup deployer account for test
        let deployer_addr = signer::address_of(deployer);
        aptos_framework::account::create_account_for_test(deployer_addr);
        aptos_framework::account::create_account_for_test(signer::address_of(owner));

        // setup test components
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TIMESTAMP);
        chain_id::initialize_for_test(framework, CHAIN_ID as u8);

        mcms_account::init_module_for_testing(deployer);

        mcms::init_module_for_testing(deployer);

        deployer_addr
    }

    #[test_only]
    struct ExecuteArgs has drop {
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function: String,
        data: vector<u8>,
        proof: vector<vector<u8>>
    }

    #[test_only]
    fun default_execute_args(): ExecuteArgs {
        ExecuteArgs {
            role: mcms::proposer_role(),
            chain_id: CHAIN_ID,
            multisig: @mcms,
            nonce: OP1_NONCE,
            to: @mcms,
            module_name: string::utf8(b"mcms"),
            function: string::utf8(b"timelock_schedule_batch"),
            data: OP1_DATA,
            proof: OP1_PROOF
        }
    }

    #[test_only]
    fun call_execute(args: ExecuteArgs) {
        mcms::execute(
            args.role,
            args.chain_id,
            args.multisig,
            args.nonce,
            args.to,
            args.module_name,
            args.function,
            args.data,
            args.proof
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    /// 0xa969156fce9a4f08bcdc07b90f338efc630bff8dfa8340500cb6414aca762a4e must be the mcms address,
    /// as this is `multisig` address in the root metadata tests
    public fun test_e2e(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );

        let multisig = mcms::multisig_object(role);
        let signers = mcms::signers(multisig);
        assert!(simple_map::length(&signers) == 3, 0);

        let set_root_args = default_set_root_args(false);
        call_set_root(set_root_args);

        let (root, valid_until, op_count) = mcms::expiring_root_and_op_count(multisig);
        assert!(root == ROOT, 1);
        assert!(valid_until == VALID_UNTIL, 2);
        assert!(op_count == 0, 3);

        // First we must transfer ownership to `@mcms` (the multisig/self)
        mcms_account::transfer_ownership_to_self(owner);

        // Schedule this op via `mcms::execute`, we serialize schedule_batch data to @mcms
        let execute_args = default_execute_args();
        call_execute(execute_args);

        // Wait for delay (1)
        timestamp::update_global_time_for_test_secs(TIMESTAMP + 10);

        // check op count incremented
        let (_post_execute_root, _post_execute_valid_until, post_execute_op_count) =
            mcms::expiring_root_and_op_count(multisig);
        assert!(post_execute_op_count == 1, 4);

        // Now we call execute_batch to execute the scheduled op (mcms_account::accept_ownership)
        mcms::timelock_execute_batch(
            vector[@mcms],
            vector[string::utf8(b"mcms_account")],
            vector[string::utf8(b"accept_ownership")],
            vector[vector[]],
            mcms::zero_hash(),
            vector[]
        );

        // Verify new owner is now `@mcms`
        let new_mcms_owner = mcms_account::owner();
        assert!(new_mcms_owner == @mcms, 5);
    }

    //// set_root tests ////
    #[test_only]
    /// bcs_helper struct for set_root args in tests
    struct SetRootArgs has drop {
        role: u8,
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

    fun default_set_root_args(override_previous_root: bool): SetRootArgs {
        SetRootArgs {
            role: mcms::proposer_role(),
            root: ROOT,
            valid_until: VALID_UNTIL,
            chain_id: CHAIN_ID,
            multisig: @mcms,
            pre_op_count: PRE_OP_COUNT,
            post_op_count: POST_OP_COUNT,
            override_previous_root,
            metadata_proof: METADATA_PROOF,
            signatures: SIGNATURES
        }
    }

    fun call_set_root(args: SetRootArgs) {
        mcms::set_root(
            args.role,
            args.root,
            args.valid_until,
            args.chain_id,
            args.multisig,
            args.pre_op_count,
            args.post_op_count,
            args.override_previous_root,
            args.metadata_proof,
            args.signatures
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_ALREADY_SEEN_HASH, location = mcms::mcms)]
    public fun test_set_root__already_seen_hash(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );

        // first call success
        let set_root_args = default_set_root_args(false);
        call_set_root(set_root_args);

        // second call should fail as the hash has already been seen
        let set_root_args2 = default_set_root_args(false);
        call_set_root(set_root_args2);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_VALID_UNTIL_EXPIRED, location = mcms::mcms)]
    public fun test_set_root__valid_until_expired(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let set_root_args = default_set_root_args(false);
        set_root_args.valid_until = TIMESTAMP - 1; // set valid_until to a time in the past
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INVALID_ROOT_LEN, location = mcms::mcms)]
    public fun test_set_root__invalid_root_len(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let invalid_root =
            x"8ad6edb34398f637ca17e46b0b51ce50e18f56287aa0bf728ae3b5c4119c16";
        let set_root_args = default_set_root_args(false);
        set_root_args.root = invalid_root;
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_CHAIN_ID, location = mcms::mcms)]
    public fun test_set_root__invalid_chain_id(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let set_root_args = default_set_root_args(false);
        set_root_args.chain_id = 111; // wrong chain id
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_MULTISIG, location = mcms::mcms)]
    public fun test_set_root__invalid_multisig_addr(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let set_root_args = default_set_root_args(false);
        set_root_args.multisig = @0x12345; // wrong multisig address
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_PENDING_OPS, location = mcms::mcms)]
    public fun test_set_root__pending_ops(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let multisig = mcms::multisig_object(mcms::proposer_role());
        mcms::test_set_expiring_root_and_op_count(multisig, ROOT, VALID_UNTIL, 1);
        mcms::test_set_root_metadata(
            multisig,
            mcms::proposer_role(),
            CHAIN_ID,
            object::object_address(&multisig),
            0,
            2,
            false
        );
        let set_root_args = default_set_root_args(false);
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_PROOF_CANNOT_BE_VERIFIED, location = mcms::mcms
    )]
    public fun test_set_root__override_previous_root(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let set_root_args = default_set_root_args(false);
        // Change the post_op_count to a value that is not equal to the proof's post_op_count
        set_root_args.post_op_count = 20;
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_PRE_OP_COUNT, location = mcms::mcms)]
    public fun test_set_root__wrong_pre_op_count(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let set_root_args = default_set_root_args(false);
        set_root_args.pre_op_count = 1; // wrong pre op count, should equal op count (0)
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_POST_OP_COUNT, location = mcms::mcms)]
    public fun test_set_root__wrong_post_op_count(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let multisig = mcms::multisig_object(mcms::proposer_role());
        mcms::test_set_expiring_root_and_op_count(multisig, ROOT, VALID_UNTIL, 1);
        mcms::test_set_root_metadata(
            multisig,
            mcms::proposer_role(),
            CHAIN_ID,
            object::object_address(&multisig),
            0,
            1,
            false
        );

        let set_root_args = default_set_root_args(false);
        set_root_args.pre_op_count = PRE_OP_COUNT + 1; // correct pre op count after state updates
        set_root_args.post_op_count = PRE_OP_COUNT; // post op count should be >= pre op count
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_PROOF_CANNOT_BE_VERIFIED, location = mcms::mcms
    )]
    public fun test_set_root__empty_metadata_proof(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let set_root_args = default_set_root_args(false);
        set_root_args.metadata_proof = vector[]; // empty proof
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_PROOF_CANNOT_BE_VERIFIED, location = mcms::mcms
    )]
    public fun test_set_root__metadata_not_consistent_with_proof(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let set_root_args = default_set_root_args(false);
        set_root_args.post_op_count = POST_OP_COUNT + 1; // post op count modified
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_MISSING_CONFIG, location = mcms::mcms)]
    public fun test_set_root__config_not_set(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let set_root_args = default_set_root_args(false);
        set_root_args.signatures = vector[]; // no signatures
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[
        expected_failure(
            abort_code = mcms::mcms::E_SIGNER_ADDR_MUST_BE_INCREASING, location = mcms::mcms
        )
    ]
    public fun test_set_root__out_of_order_signatures(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let set_root_args = default_set_root_args(false);
        let sig0 = set_root_args.signatures.borrow(0);
        let sig1 = set_root_args.signatures.borrow(1);
        let sig2 = set_root_args.signatures.borrow(2);
        set_root_args.signatures = vector[*sig0, *sig2, *sig1]; // shuffle signature order
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INVALID_SIGNER, location = mcms::mcms)]
    public fun test_set_root__signature_from_invalid_signer(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let set_root_args = default_set_root_args(false);
        let invalid_signer_sig =
            x"bb7f7e44b8d9c8f978c255c7efd6abb64e8fa9a33dcb6db2e2203d8aacd51dd471113ca6c8d1ed56bb0395f0bef0daf2fae6ef2cb5c86c57d148c7de473383461B";
        set_root_args.signatures = vector[invalid_signer_sig]; // add signature from invalid signer
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INSUFFICIENT_SIGNERS, location = mcms::mcms)]
    public fun test_set_root__signer_quorum_not_met(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let set_root_args = default_set_root_args(false);
        let signer1 = set_root_args.signatures[0];
        set_root_args.signatures = vector[signer1]; // only 1 signature, quorum is 2
        call_set_root(set_root_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_set_root__success(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let expected_role = mcms::proposer_role();
        mcms::set_config(
            owner,
            expected_role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let multisig = mcms::multisig_object(expected_role);
        let set_root_args = default_set_root_args(false);

        call_set_root(set_root_args);

        let (root, valid_until, op_count) = mcms::expiring_root_and_op_count(multisig);
        assert!(root == ROOT, 0);
        assert!(valid_until == VALID_UNTIL, 1);
        assert!(op_count == PRE_OP_COUNT, 2);

        let root_metadata = mcms::root_metadata(multisig);
        assert!(mcms::role(root_metadata) == expected_role, 2);
        assert!(mcms::chain_id(root_metadata) == CHAIN_ID, 3);
        assert!(mcms::root_metadata_multisig(root_metadata) == @mcms, 4);
        assert!(mcms::pre_op_count(root_metadata) == PRE_OP_COUNT, 5);
        assert!(mcms::post_op_count(root_metadata) == POST_OP_COUNT, 6);
        assert!(mcms::override_previous_root(root_metadata) == false, 7);
    }

    //// set_config tests ////
    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = 327683, location = mcms::mcms_account)]
    public fun test_set_config__caller_is_not_owner(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let (not_owner, _) = account::create_resource_account(deployer, b"seed123");
        mcms::set_config(
            &not_owner,
            mcms::proposer_role(),
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INVALID_NUM_SIGNERS, location = mcms::mcms)]
    public fun test_set_config__invalid_number_of_signers(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        // empty signer addresses and groups
        let signer_addr = vector[];
        let signer_group = vector[];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            signer_group,
            vector[],
            vector[],
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[
        expected_failure(
            abort_code = mcms::mcms::E_SIGNER_ADDR_MUST_BE_INCREASING, location = mcms::mcms
        )
    ]
    public fun test_set_config__signers_must_be_distinct(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        // same signer address twice
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR2];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[
        expected_failure(
            abort_code = mcms::mcms::E_SIGNER_ADDR_MUST_BE_INCREASING, location = mcms::mcms
        )
    ]
    public fun test_set_config__signers_must_be_increasing(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        // signer addresses out of order
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR3, PROPOSER_ADDR2];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_INVALID_SIGNER_ADDR_LEN, location = mcms::mcms
    )]
    public fun test_set_config__invalid_signer_address(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        // signer address not 20 bytes
        let invalid_signer_addr = x"E37ca797F7fCCFbd9bb3bf8f812F19C3184df1";
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, invalid_signer_addr];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_OUT_OF_BOUNDS_GROUP, location = mcms::mcms)]
    public fun test_set_config__out_of_bounds_signer_group(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // signer group out of bounds
        let signer_groups: vector<u8> = vector[1, 2, mcms::num_groups() as u8];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            signer_groups,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_OUT_OF_BOUNDS_GROUP_QUORUM, location = mcms::mcms
    )]
    public fun test_set_config__out_of_bounds_group_quorum(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // group quorum out of bounds (greater than num signers)
        let group_quorums = vector[2, 1, 1, (mcms::max_num_signers() as u8) + 1];
        params::right_pad_vec(&mut group_quorums, mcms::num_groups());
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            group_quorums,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_GROUP_TREE_NOT_WELL_FORMED, location = mcms::mcms
    )]
    public fun test_set_config__root_is_not_its_own_parent(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // group parent of root is group 1 (should be itself = group 0)
        let group_parents = vector[1];
        params::right_pad_vec(&mut group_parents, mcms::num_groups());
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            group_parents,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_GROUP_TREE_NOT_WELL_FORMED, location = mcms::mcms
    )]
    public fun test_set_config__non_root_is_its_own_parent(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // group parent of group 1 is itself (should be lower index group)
        let group_parents = vector[0, 1];
        params::right_pad_vec(&mut group_parents, mcms::num_groups());
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            group_parents,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_GROUP_TREE_NOT_WELL_FORMED, location = mcms::mcms
    )]
    public fun test_set_config__group_parent_higher_index(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // group parent of group 1 is group 2 (should be lower index group)
        let group_parents = vector[0, 2];
        params::right_pad_vec(&mut group_parents, mcms::num_groups());
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            group_parents,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_OUT_OF_BOUNDS_GROUP_QUORUM, location = mcms::mcms
    )]
    public fun test_set_config__quorum_cannot_be_met(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // group quorum of group 0 (root) is 4, which can never be met because there are only three child groups
        let group_quorum = vector[4, 1, 1, 1];
        params::right_pad_vec(&mut group_quorum, mcms::num_groups());
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            group_quorum,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_SIGNER_IN_DISABLED_GROUP, location = mcms::mcms
    )]
    public fun test_set_config__signer_in_disabled_group(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // group 31 is disabled (quorum = 0) but signer 3 is in group 31
        let signer_groups = vector[1, 2, 31];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            signer_groups,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_SIGNER_GROUPS_LEN_MISMATCH, location = mcms::mcms
    )]
    public fun test_set_config__signer_group_len_mismatch(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        // len of signer groups does not match len of signers
        let signer_groups = vector[1, 2, 3, 3];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            signer_groups,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_set_config__success(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // manually modify root state to check for modifications
        let role = mcms::proposer_role();
        let multisig = mcms::multisig_object(role);
        let new_op_count = 5;
        mcms::test_set_expiring_root_and_op_count(
            multisig,
            ROOT,
            VALID_UNTIL,
            new_op_count
        );
        mcms::test_set_root_metadata(
            multisig,
            role,
            1,
            @0xabc,
            new_op_count,
            new_op_count,
            false
        );

        // test set config with clear_root=false
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let config = mcms::get_config(role);
        assert!(vector::length(&mcms::config_signers(&config)) == 3, 1);
        let (addr1, index1, group1) =
            mcms::signer_view(&mcms::config_signers(&config)[0]);
        assert!(addr1 == PROPOSER_ADDR1, 2);
        assert!(index1 == 0, 3);
        assert!(group1 == 0, 4);
        let (addr2, index2, group2) =
            mcms::signer_view(&mcms::config_signers(&config)[1]);
        assert!(addr2 == PROPOSER_ADDR2, 5);
        assert!(index2 == 1, 6);
        assert!(group2 == 0, 7);
        let (addr3, index3, group3) =
            mcms::signer_view(&mcms::config_signers(&config)[2]);
        assert!(addr3 == PROPOSER_ADDR3, 8);
        assert!(index3 == 2, 9);
        assert!(group3 == 0, 10);
        assert!(mcms::config_group_quorums(&config) == GROUP_QUORUMS, 11);
        assert!(mcms::config_group_parents(&config) == GROUP_PARENTS, 12);

        let (root, valid_until, op_count) = mcms::expiring_root_and_op_count(multisig);
        assert!(root == ROOT, 7);
        assert!(valid_until == VALID_UNTIL, 8);
        assert!(op_count == new_op_count, 9);

        let root_metadata = mcms::root_metadata(multisig);
        assert!(mcms::role(root_metadata) == role, 10);
        assert!(mcms::chain_id(root_metadata) == 1, 11);
        assert!(mcms::root_metadata_multisig(root_metadata) == @0xabc, 12);
        assert!(mcms::pre_op_count(root_metadata) == 5, 13);
        assert!(mcms::post_op_count(root_metadata) == 5, 14);
        assert!(!mcms::override_previous_root(root_metadata), 15);

        // test set config with clear_root=true, change to 1-of-2 multisig with a nested 2-of-2 multisig
        let signer_addr = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        let signer_groups = vector[1, 3, 4];
        let group_quorums = vector[1, 1, 2, 1, 1];
        params::right_pad_vec(&mut group_quorums, mcms::num_groups());
        let group_parents = vector[0, 0, 0, 2, 2];
        params::right_pad_vec(&mut group_parents, mcms::num_groups());
        mcms::set_config(
            owner,
            mcms::proposer_role(),
            signer_addr,
            signer_groups,
            group_quorums,
            group_parents,
            true
        );
        let config = mcms::get_config(role);
        assert!(vector::length(&mcms::config_signers(&config)) == 3, 14);
        let (addr1, index1, group1) =
            mcms::signer_view(&mcms::config_signers(&config)[0]);
        let (addr2, index2, group2) =
            mcms::signer_view(&mcms::config_signers(&config)[1]);
        let (addr3, index3, group3) =
            mcms::signer_view(&mcms::config_signers(&config)[2]);
        assert!(addr1 == PROPOSER_ADDR1, 15);
        assert!(index1 == 0, 16);
        assert!(group1 == 1, 17);
        assert!(addr2 == PROPOSER_ADDR2, 18);
        assert!(index2 == 1, 19);
        assert!(group2 == 3, 20);
        assert!(addr3 == PROPOSER_ADDR3, 21);
        assert!(index3 == 2, 22);
        assert!(group3 == 4, 23);
        assert!(group_quorums == group_quorums, 24);
        assert!(group_parents == group_parents, 25);

        let (root, valid_until, op_count) = mcms::expiring_root_and_op_count(multisig);
        assert!(root == vector[], 20);
        assert!(valid_until == 0, 21);
        assert!(op_count == new_op_count, 22);

        let root_metadata = mcms::root_metadata(multisig);
        assert!(mcms::role(root_metadata) == role, 23);
        assert!(mcms::chain_id(root_metadata) == CHAIN_ID, 24);
        assert!(mcms::root_metadata_multisig(root_metadata) == @mcms, 25);
        assert!(mcms::pre_op_count(root_metadata) == new_op_count, 26);
        assert!(mcms::post_op_count(root_metadata) == new_op_count, 27);
        assert!(mcms::override_previous_root(root_metadata), 28);
    }

    //// ============== execute tests ============== ////
    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_POST_OP_COUNT_REACHED, location = mcms::mcms)]
    public fun test_execute__root_not_set(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        // since root not set, post op count is 0 which is not greater than current op count (also 0)
        let execute_args = default_execute_args();
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_POST_OP_COUNT_REACHED, location = mcms::mcms)]
    public fun test_execute__post_op_count_reached(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let multisig = mcms::multisig_object(role);
        call_set_root(default_set_root_args(false));
        let root_metadata = mcms::root_metadata(multisig);
        let post_op_count = mcms::post_op_count(root_metadata);
        // set current op count to post op count
        mcms::test_set_expiring_root_and_op_count(
            multisig,
            ROOT,
            VALID_UNTIL,
            post_op_count
        );
        let execute_args = default_execute_args();
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_CHAIN_ID, location = mcms::mcms)]
    public fun test_execute__wrong_chain_id(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        call_set_root(default_set_root_args(false));
        let execute_args = default_execute_args();
        execute_args.chain_id = 111; // wrong chain id
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_MULTISIG, location = mcms::mcms)]
    public fun test_execute__wrong_multisig_addr(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        call_set_root(default_set_root_args(false));
        let execute_args = default_execute_args();
        execute_args.multisig = @0x12345; // wrong multisig address
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_ROOT_EXPIRED, location = mcms::mcms)]
    public fun test_execute__root_expired(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            true
        );
        let multisig = mcms::multisig_object(role);
        call_set_root(default_set_root_args(false));

        // modify valid until state directly - set valid_until to a time in the past
        mcms::test_set_expiring_root_and_op_count(multisig, ROOT, TIMESTAMP - 1, 0);
        let execute_args = default_execute_args();
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_NONCE, location = mcms::mcms)]
    public fun test_execute__wrong_nonce(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        call_set_root(default_set_root_args(false));
        let execute_args = default_execute_args();
        execute_args.nonce += 1; // wrong nonce
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_PROOF_CANNOT_BE_VERIFIED, location = mcms::mcms
    )]
    public fun test_execute__bad_op_proof(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        call_set_root(default_set_root_args(false));
        let execute_args = default_execute_args();
        execute_args.data = b"different data"; // modify op so proof verification should fail
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(
        abort_code = mcms::mcms::E_PROOF_CANNOT_BE_VERIFIED, location = mcms::mcms
    )]
    public fun test_execute__empty_proof(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        call_set_root(default_set_root_args(false));
        let execute_args = default_execute_args();
        execute_args.proof = vector[]; // empty proof
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_WRONG_NONCE, location = mcms::mcms)]
    public fun test_execute__ops_executed_out_of_order(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            false
        );
        let multisig = mcms::multisig_object(role);
        // modify state to add pending ops to a different one from OP1_NONCE
        mcms::test_set_expiring_root_and_op_count(
            multisig,
            ROOT,
            VALID_UNTIL,
            OP1_NONCE + 1
        );

        mcms::test_set_root_metadata(
            multisig,
            role,
            CHAIN_ID,
            @mcms,
            0, // pre_op_count
            2, // post_op_count
            false
        );

        let execute_args = default_execute_args();
        call_execute(execute_args);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_ownable__transfer_ownership(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let new_owner = signer::address_of(deployer);
        mcms_account::transfer_ownership(owner, new_owner);
        mcms_account::accept_ownership(deployer);
        let updated_owner = mcms_account::owner();
        assert!(updated_owner == new_owner, 1);
    }

    // //// ============== Utility function tests ============== ////
    #[test]
    public fun test_utils__hash_metadata_leaf() {
        let role = 2;
        let chain_id = 4;
        let multisig =
            @0x5c94246eff0f850c4622ea6987c2217e5ead39243f951a718671ad6c58a2c193;
        let pre_op_count = 0;
        let post_op_count = 4;
        let override_previous_root = false;
        let hash =
            mcms::test_hash_metadata_leaf(
                role,
                chain_id,
                multisig,
                pre_op_count,
                post_op_count,
                override_previous_root
            );
        // test output computed from equivalent solidity function: keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA, metadata))
        assert!(
            hash == x"d41afb7a1c2061ff8f71863772a6be55fa09c6271463e6f3d6b5f25ffbc415f7",
            1
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_utils__hash_op_leaf(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let role = mcms::proposer_role();
        // Create an Op similar to what we use in test_verify_merkle_proof_with_hash_op
        let chain_id = CHAIN_ID;
        let nonce = OP1_NONCE;
        let to = @mcms;
        let module_name = string::utf8(b"mcms");
        let function = string::utf8(b"timelock_schedule_batch");
        let data = OP1_DATA;

        let op = mcms::create_op(
            role,
            chain_id,
            @mcms,
            nonce,
            to,
            module_name,
            function,
            data
        );
        let hash = mcms::hash_op_leaf(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP, op);
        // test output computed from equivalent solidity function: keccak256(abi.encode(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP, op))
        let expected_hash = LEAVES[1];
        assert!(hash == expected_hash, 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_verify_merkle_proof_with_hash_op(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let role = mcms::proposer_role();

        let chain_id = CHAIN_ID;
        let nonce = OP1_NONCE;
        let to = @mcms;
        let module_name = string::utf8(b"mcms");
        let function = string::utf8(b"timelock_schedule_batch");
        let data = OP1_DATA;
        let expected_root = ROOT;
        let expected_leaf_hash = LEAVES[1]; // Get the first OP hash
        let op = mcms::create_op(
            role,
            chain_id,
            @mcms,
            nonce,
            to,
            module_name,
            function,
            data
        );
        let computed_leaf_hash =
            mcms::hash_op_leaf(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP, op);

        assert!(computed_leaf_hash == expected_leaf_hash, 0);
        assert!(
            mcms::verify_merkle_proof(OP1_PROOF, expected_root, computed_leaf_hash),
            0
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_different_group_structures(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // This test verifies a multisig structure with nested groups to ensure
        // the MCMS system correctly handles hierarchical signer configurations

        // ==================== Group Structure ====================
        // Create a hierarchical structure as follows:
        //
        // Root Group (index 0): Requires 2-of-3 approvals from its children:
        //     +-- Group 1 (index 1): Requires 1-of-2 approvals
        //     |   +-- Signer 1 (in Group 3)
        //     |   +-- Signer 2 (in Group 4)
        //     |
        //     +-- Group 2 (index 2): Requires 1 approval
        //     |   +-- Signer 3
        //     |
        //     +-- (No direct signers in root group)
        //
        // This structure means to execute a transaction:
        // - Either Signer 3 + (Signer 1 OR Signer 2) must approve
        // - OR any other valid combination meeting the 2-of-3 quorum at the root level
        // ============================================================

        let signer_addresses = vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3];
        let signer_groups = vector[3, 4, 2]; // Signer 1 in Group 3, Signer 2 in Group 4, Signer 3 in Group 2

        // Define quorum for each group (how many approvals needed)
        // Root Group (0): needs 2 approvals
        // Group 1 (1): needs 1 approval from its children
        // Group 2 (2): needs 1 approval
        // Group 3 (3): needs 1 approval (leaf group with Signer 1)
        // Group 4 (4): needs 1 approval (leaf group with Signer 2)
        let group_quorums = vector[2, 1, 1, 1, 1];
        params::right_pad_vec(&mut group_quorums, mcms::num_groups());

        // Define the group hierarchy (which group is parent of which)
        // Group 0: parent is itself (root)
        // Group 1: parent is root (0)
        // Group 2: parent is root (0)
        // Group 3: parent is Group 1
        // Group 4: parent is Group 1
        let group_parents = vector[0, 0, 0, 1, 1];
        params::right_pad_vec(&mut group_parents, mcms::num_groups());

        // Configure the multisig structure for a bypasser role
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            signer_addresses,
            signer_groups,
            group_quorums,
            group_parents,
            false
        );

        // Retrieve the current configuration
        let config = mcms::get_config(role);
        assert!(vector::length(&mcms::config_signers(&config)) == 3, 0); // Verify we have 3 signers

        // Verify signer assignments to their respective groups
        let (_, _, group1) = mcms::signer_view(&mcms::config_signers(&config)[0]); // Group of Signer 1
        let (_, _, group2) = mcms::signer_view(&mcms::config_signers(&config)[1]); // Group of Signer 2
        let (_, _, group3) = mcms::signer_view(&mcms::config_signers(&config)[2]); // Group of Signer 3

        assert!(group1 == 3, 1); // Signer 1 should be in Group 3
        assert!(group2 == 4, 2); // Signer 2 should be in Group 4
        assert!(group3 == 2, 3); // Signer 3 should be in Group 2

        // Verify group quorums (number of approvals needed per group)
        assert!(mcms::config_group_quorums(&config)[0] == 2, 4); // Root group requires 2 approvals
        assert!(mcms::config_group_quorums(&config)[1] == 1, 5); // Group 1 requires 1 approval
        assert!(mcms::config_group_quorums(&config)[2] == 1, 6); // Group 2 requires 1 approval
        assert!(mcms::config_group_quorums(&config)[3] == 1, 7); // Group 3 requires 1 approval
        assert!(mcms::config_group_quorums(&config)[4] == 1, 8); // Group 4 requires 1 approval

        // Verify group hierarchy (parent-child relationships)
        assert!(mcms::config_group_parents(&config)[0] == 0, 9); // Root is its own parent
        assert!(mcms::config_group_parents(&config)[1] == 0, 10); // Group 1's parent is the root
        assert!(mcms::config_group_parents(&config)[2] == 0, 11); // Group 2's parent is the root
        assert!(mcms::config_group_parents(&config)[3] == 1, 12); // Group 3's parent is Group 1
        assert!(mcms::config_group_parents(&config)[4] == 1, 13); // Group 4's parent is Group 1
    }

    // ==================== Timelock Tests ================== //
    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_timelock_initialization(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let min_delay = mcms::timelock_min_delay();
        assert!(min_delay == 0, 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_update_min_delay(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms::test_timelock_update_min_delay(MIN_DELAY);
        assert!(mcms::timelock_min_delay() == MIN_DELAY, 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_schedule_batch(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"timelock_update_min_delay")];
        let data = bcs::to_bytes(&MIN_DELAY);
        let datas = vector[data];

        // Schedule batch operation
        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            TEST_PREDECESSOR,
            TEST_SALT,
            MIN_DELAY
        );

        let calls = mcms::create_calls(targets, module_names, function_names, datas);
        let id = mcms::hash_operation_batch(calls, TEST_PREDECESSOR, TEST_SALT);

        // Verify operation is pending
        assert!(mcms::timelock_is_operation_pending(id), 0);

        // Verify timestamp is set correctly
        let timestamp_value = mcms::timelock_get_timestamp(id);
        assert!(timestamp_value > TIMESTAMP, 1);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_cancel_operation(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"timelock_update_min_delay")];
        let data = bcs::to_bytes(&MIN_DELAY);
        let datas = vector[data];

        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            TEST_PREDECESSOR,
            TEST_SALT,
            MIN_DELAY
        );

        // Calculate the operation ID
        let calls = mcms::create_calls(targets, module_names, function_names, datas);
        let id = mcms::hash_operation_batch(calls, TEST_PREDECESSOR, TEST_SALT);

        // Verify operation is pending
        assert!(mcms::timelock_is_operation_pending(id));

        // Cancel the operation
        mcms::test_timelock_cancel(id);

        // Verify operation is no longer pending
        assert!(!mcms::timelock_is_operation_pending(id));
        assert!(!mcms::timelock_is_operation(id));
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_bypasser_execute_batch(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);

        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"timelock_update_min_delay")];
        let datas = vector[bcs::to_bytes(&MIN_DELAY)];

        mcms::test_timelock_bypasser_execute_batch(
            targets,
            module_names,
            function_names,
            datas
        );

        let updated_delay = mcms::timelock_min_delay();
        assert!(updated_delay == MIN_DELAY, 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_block_unblock_function(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        mcms::test_timelock_block_function(
            TEST_TARGET_ADDRESS,
            string::utf8(b"test_module"),
            string::utf8(b"test_function")
        );

        // Verify the function is blocked
        let blocked_count = mcms::timelock_get_blocked_functions_count();
        assert!(blocked_count == 1, 0);

        let function = mcms::timelock_get_blocked_function(0);
        assert!(
            mcms::function_name(function) == string::utf8(b"test_function")
                && mcms::module_name(function) == string::utf8(b"test_module")
                && mcms::target(function) == TEST_TARGET_ADDRESS,
            0
        );
        // Unblock the function
        mcms::test_timelock_unblock_function(
            TEST_TARGET_ADDRESS,
            string::utf8(b"test_module"),
            string::utf8(b"test_function")
        );

        // Verify the function is unblocked
        let blocked_count_after = mcms::timelock_get_blocked_functions_count();
        assert!(blocked_count_after == 0, 2);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INVALID_PARAMETERS, location = mcms::mcms)]
    public fun test_schedule_batch_invalid_parameters(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Try to schedule with mismatched parameters length
        mcms::test_timelock_schedule_batch(
            vector[@mcms, @mcms], // 2 targets
            vector[string::utf8(b"test_module")], // But only 1 module name
            vector[string::utf8(b"test_function")],
            vector[vector[0u8]],
            vector[],
            vector[],
            0
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INSUFFICIENT_DELAY, location = mcms::mcms)]
    public fun test_schedule_insufficient_delay(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // First set a minimum delay
        mcms::test_timelock_update_min_delay(MIN_DELAY);

        // Try to schedule with delay lower than minimum
        mcms::test_timelock_schedule_batch(
            vector[@mcms],
            vector[string::utf8(b"test_module")],
            vector[string::utf8(b"test_function")],
            vector[vector[0u8]],
            vector[],
            vector[1u8],
            MIN_DELAY - 1
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[
        expected_failure(
            abort_code = mcms::mcms::E_OPERATION_ALREADY_SCHEDULED, location = mcms::mcms
        )
    ]
    public fun test_schedule_already_scheduled(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"test_module")];
        let function_names = vector[string::utf8(b"test_function")];
        let datas = vector[vector[0u8]];
        let predecessor = vector[];
        let salt = vector[1u8];

        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            0
        );

        // Try to schedule the same batch again
        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            0
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_FUNCTION_BLOCKED, location = mcms::mcms)]
    public fun test_schedule_blocked_function(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        mcms::test_timelock_block_function(
            TEST_TARGET_ADDRESS,
            string::utf8(b"test_module"),
            string::utf8(b"test_function")
        );

        mcms::test_timelock_schedule_batch(
            vector[TEST_TARGET_ADDRESS],
            vector[string::utf8(b"test_module")],
            vector[string::utf8(b"test_function")],
            vector[vector[0u8]],
            vector[],
            vector[],
            0
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_OPERATION_NOT_READY, location = mcms::mcms)]
    public fun test_execute_batch_not_ready(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"test_module")];
        let function_names = vector[string::utf8(b"test_function")];
        let datas = vector[vector[0u8]];
        let predecessor = vector[];
        let salt = vector[1u8];

        let delay = 100000;
        mcms::test_timelock_update_min_delay(delay);

        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            delay
        );

        // Try to execute before the delay has passed
        mcms::timelock_execute_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[
        expected_failure(
            abort_code = mcms::mcms::E_OPERATION_CANNOT_BE_CANCELLED, location = mcms::mcms
        )
    ]
    public fun test_cancel_nonexistent_operation(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms::test_timelock_cancel(vector[123u8]);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INVALID_INDEX, location = mcms::mcms)]
    public fun test_get_blocked_function_invalid_index(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Block a function
        mcms::test_timelock_block_function(
            TEST_TARGET_ADDRESS,
            string::utf8(b"test_module"),
            string::utf8(b"test_function")
        );

        // Try to get a blocked function with an invalid index
        let _function = mcms::timelock_get_blocked_function(1);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_idempotent_block_function(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Block a function
        mcms::test_timelock_block_function(
            TEST_TARGET_ADDRESS,
            string::utf8(b"test_module"),
            string::utf8(b"test_function")
        );

        // Block it again (should be idempotent)
        mcms::test_timelock_block_function(
            TEST_TARGET_ADDRESS,
            string::utf8(b"test_module"),
            string::utf8(b"test_function")
        );

        // Count should still be 1
        let count = mcms::timelock_get_blocked_functions_count();
        assert!(count == 1, 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_MISSING_DEPENDENCY, location = mcms::mcms)]
    public fun test_execute_batch_missing_dependency(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Create two batches with a dependency relationship
        let targets1 = vector[@mcms];
        let module_names1 = vector[string::utf8(b"test_module")];
        let function_names1 = vector[string::utf8(b"test_function1")];
        let datas1 = vector[vector[0u8]];
        let predecessor1 = vector[];
        let salt1 = vector[1u8];

        // First, schedule the first batch
        mcms::test_timelock_schedule_batch(
            targets1,
            module_names1,
            function_names1,
            datas1,
            predecessor1,
            salt1,
            0 // Immediate execution
        );

        // Generate a unique identifier for the second batch
        let salt2 = vector[2u8];
        let predecessor2 = x"deadbeef"; // Use a non-existent operation ID as a predecessor

        // Schedule second batch with dependency on non-existent operation
        let targets2 = vector[@mcms];
        let module_names2 = vector[string::utf8(b"test_module")];
        let function_names2 = vector[string::utf8(b"test_function2")];
        let datas2 = vector[vector[0u8]];

        mcms::test_timelock_schedule_batch(
            targets2,
            module_names2,
            function_names2,
            datas2,
            predecessor2, // This batch depends on a non-existent batch
            salt2,
            0 // Immediate execution
        );

        // Try to execute the second batch, should fail with E_MISSING_DEPENDENCY
        mcms::timelock_execute_batch(
            targets2,
            module_names2,
            function_names2,
            datas2,
            predecessor2,
            salt2
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[
        expected_failure(
            abort_code = mcms::mcms::E_UNKNOWN_MCMS_MODULE_FUNCTION, location = mcms::mcms
        )
    ]
    public fun test_execute_unknown_function(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Create call data for a non-existent function in mcms
        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"nonexistent_function")];
        let datas = vector[vector[0u8]];
        let predecessor = mcms::zero_hash();
        let salt = vector[1u8];

        // Schedule the batch with the non-existent function
        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            0 // Immediate execution
        );

        // Fast forward time to make the operation executable
        timestamp::update_global_time_for_test_secs(TIMESTAMP + 10);

        // Execute the batch - this should fail with E_UNKNOWN_MCMS_MODULE_FUNCTION
        mcms::timelock_execute_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_OPERATION_NOT_READY, location = mcms::mcms)]
    public fun test_execute_unscheduled_operation(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        // Create call data for a function
        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"timelock_update_min_delay")];
        let datas = vector[bcs::to_bytes(&MIN_DELAY)];
        let predecessor = mcms::zero_hash();
        let salt = vector[1u8];

        // Try to execute without scheduling first - should fail with E_OPERATION_NOT_READY
        mcms::timelock_execute_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_OPERATION_NOT_READY, location = mcms::mcms)]
    public fun test_execute_batch_after_completion(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);

        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"timelock_update_min_delay")];
        let data = bcs::to_bytes(&MIN_DELAY);
        let datas = vector[data];
        let predecessor = mcms::zero_hash();
        let salt = vector[1u8];

        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            0 // Immediate execution
        );

        // Execute it first time
        mcms::timelock_execute_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt
        );

        // Try to execute it a second time - should fail with E_OPERATION_NOT_READY
        mcms::timelock_execute_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_bypasser_execute_blocked_function(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);

        let target = @mcms;
        let module_name = string::utf8(b"mcms");
        let function_name = string::utf8(b"timelock_update_min_delay");

        mcms::test_timelock_block_function(target, module_name, function_name);

        // Bypasser should be able to directly execute the blocked function
        let targets = vector[target];
        let module_names = vector[module_name];
        let function_names = vector[function_name];
        let data = bcs::to_bytes(&MIN_DELAY);
        let datas = vector[data];

        // Should succeed since bypassers/owner can execute blocked functions
        mcms::test_timelock_bypasser_execute_batch(
            targets,
            module_names,
            function_names,
            datas
        );

        // Verify the min delay was updated despite being blocked
        assert!(mcms::timelock_min_delay() == MIN_DELAY, 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_execute_batch_with_dependencies(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);

        let targets_1 = vector[@mcms];
        let module_names_1 = vector[string::utf8(b"mcms")];
        let function_names_1 = vector[string::utf8(b"timelock_update_min_delay")];
        let data = bcs::to_bytes(&MIN_DELAY);
        let datas_1 = vector[data];
        let predecessor_1 = mcms::zero_hash();
        let salt_1 = x"abcd";
        let delay = 1; // Small delay for testing

        mcms::test_timelock_schedule_batch(
            targets_1,
            module_names_1,
            function_names_1,
            datas_1,
            predecessor_1,
            salt_1,
            delay
        );

        // Calculate first operation ID for dependency
        let calls_1 =
            mcms::create_calls(
                targets_1,
                module_names_1,
                function_names_1,
                datas_1
            );
        let id_1 = mcms::hash_operation_batch(calls_1, predecessor_1, salt_1);

        // Schedule second operation with dependency on first
        let targets_2 = vector[@mcms];
        let module_names_2 = vector[string::utf8(b"mcms")];
        let function_names_2 = vector[string::utf8(b"timelock_update_min_delay")];
        let new_delay = 2;
        let data = bcs::to_bytes(&new_delay);
        let datas_2 = vector[data];
        let predecessor_2 = id_1; // Use first operation as predecessor
        let salt_2 = x"efab";

        mcms::test_timelock_schedule_batch(
            targets_2,
            module_names_2,
            function_names_2,
            datas_2,
            predecessor_2,
            salt_2,
            delay
        );

        // Update timestamp as min delay is updated
        timestamp::update_global_time_for_test_secs(TIMESTAMP + delay);

        // Execute first operation
        mcms::timelock_execute_batch(
            targets_1,
            module_names_1,
            function_names_1,
            datas_1,
            predecessor_1,
            salt_1
        );

        // Verify min delay was updated
        assert!(mcms::timelock_min_delay() == MIN_DELAY);

        // Update timestamp as min delay is updated
        timestamp::update_global_time_for_test_secs(TIMESTAMP + MIN_DELAY);

        // Execute second operation
        mcms::timelock_execute_batch(
            targets_2,
            module_names_2,
            function_names_2,
            datas_2,
            predecessor_2,
            salt_2
        );

        // Verify min delay was updated
        assert!(mcms::timelock_min_delay() == new_delay);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_bypasser_allowed_when_timelock_active(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        let delay = 1800;
        mcms::test_timelock_update_min_delay(delay);

        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);

        // This should succeed because bypassers are allowed to bypass the timelock
        let data = bcs::to_bytes(&delay);
        mcms::test_timelock_bypasser_execute_batch(
            vector[@mcms],
            vector[string::utf8(b"mcms")],
            vector[string::utf8(b"timelock_update_min_delay")],
            vector[data]
        );

        // Verify the min_delay was updated, confirming the bypass worked
        assert!(mcms::timelock_min_delay() == delay, 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_UNKNOWN_MCMS_MODULE, location = mcms::mcms)]
    public fun test_unknown_mcms_module(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"unknown_module")];
        let function_names = vector[string::utf8(b"timelock_update_min_delay")];
        let datas = vector[bcs::to_bytes(&MIN_DELAY)];
        let predecessor = mcms::zero_hash();
        let salt = vector[1u8];

        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            0
        );

        mcms::timelock_execute_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt
        );
    }

    #[test]
    public fun test_merkle__ecdsa_recover_evm_addr() {
        let eth_signed_message_hash =
            x"910cd291f5281f5bf25d8a83962f282b6c2bdf831f079dfcb84480f922abd2e1";
        let signature =
            x"45283a6239b1b559a910e97f79a52bab1605e8bd952c4b4e0720ed9b1e9e96712acab6f5f946bfa3dfa61f47705aff6e2f17f6ad83d484857bb119a06ba1f0e71C";
        let recovered_addr =
            mcms::test_ecdsa_recover_evm_addr(eth_signed_message_hash, signature);
        assert!(recovered_addr == x"16c9fACed8a1e3C6aEA2B654EEca5617eb900EFf", 1);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_view_getter_functions(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        assert!(mcms::bypasser_role() == 0);
        assert!(mcms::canceller_role() == 1);
        assert!(mcms::proposer_role() == 2);
        assert!(mcms::timelock_role() == 3);

        assert!(mcms::is_valid_role(0));

        assert!(mcms::num_groups() == 32);
        assert!(mcms::max_num_signers() == 200);
        assert!(
            mcms::zero_hash()
                == vector[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let bypasser = mcms::multisig_object(mcms::bypasser_role());
        let _canceller = mcms::multisig_object(mcms::canceller_role());
        let proposer = mcms::multisig_object(mcms::proposer_role());

        let config_bypasser = mcms::get_config(mcms::bypasser_role());
        let config_canceller = mcms::get_config(mcms::canceller_role());
        let config_proposer = mcms::get_config(mcms::proposer_role());

        let bypasser_signers = mcms::config_signers(&config_bypasser);
        let canceller_signers = mcms::config_signers(&config_canceller);
        let proposer_signers = mcms::config_signers(&config_proposer);

        assert!(vector::length(&bypasser_signers) == 0);
        assert!(vector::length(&canceller_signers) == 0);
        assert!(vector::length(&proposer_signers) == 0);

        // Test expiring root and op count getters
        let (root_bypasser, valid_until_bypasser, op_count_bypasser) =
            mcms::expiring_root_and_op_count(bypasser);
        assert!(root_bypasser.length() == 0);
        assert!(valid_until_bypasser == 0);
        assert!(op_count_bypasser == 0);

        // Test root metadata getters
        let metadata_bypasser = mcms::root_metadata(bypasser);
        assert!(mcms::role(metadata_bypasser) == mcms::bypasser_role());
        assert!(mcms::pre_op_count(metadata_bypasser) == 0);
        assert!(mcms::post_op_count(metadata_bypasser) == 0);
        assert!(!mcms::override_previous_root(metadata_bypasser));

        // Test get_root_metadata view function
        let root_metadata = mcms::get_root_metadata(mcms::proposer_role());
        assert!(mcms::role(root_metadata) == mcms::proposer_role());

        // Test get_op_count function
        let op_count = mcms::get_op_count(mcms::proposer_role());
        assert!(op_count == 0);

        // Test get_root function
        let (root, valid_until) = mcms::get_root(mcms::proposer_role());
        assert!(root.length() == 0);
        assert!(valid_until == 0);

        // Test timelock view functions
        assert!(mcms::timelock_min_delay() == 0);
        assert!(mcms::timelock_get_blocked_functions_count() == 0);

        // Test signers map functions
        let signers_map = mcms::signers(proposer);
        assert!(simple_map::length(&signers_map) == 0);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_view_getter_functions_after_config(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        // Setup the test environment
        setup(deployer, owner, framework);

        // Set a config to test view functions after configuration
        let role = mcms::proposer_role();
        mcms::set_config(
            owner,
            role,
            vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3],
            SIGNER_GROUPS,
            GROUP_QUORUMS,
            GROUP_PARENTS,
            true
        );

        // Test getting config after setting
        let config = mcms::get_config(role);
        let signers = mcms::config_signers(&config);
        assert!(vector::length(&signers) == 3, 0);

        // Test group quorums and parents getters
        let group_quorums = mcms::config_group_quorums(&config);
        let group_parents = mcms::config_group_parents(&config);
        assert!(group_quorums == GROUP_QUORUMS, 1);
        assert!(group_parents == GROUP_PARENTS, 2);

        // Test signers map after configuration
        let multisig = mcms::multisig_object(role);
        let signers_map = mcms::signers(multisig);
        assert!(simple_map::length(&signers_map) == 3, 3);
        assert!(simple_map::contains_key(&signers_map, &PROPOSER_ADDR1), 4);
        assert!(simple_map::contains_key(&signers_map, &PROPOSER_ADDR2), 5);
        assert!(simple_map::contains_key(&signers_map, &PROPOSER_ADDR3), 6);

        // Test signer_view function
        let signer1 = *simple_map::borrow(&signers_map, &PROPOSER_ADDR1);
        let (addr, index, group) = mcms::signer_view(&signer1);
        assert!(addr == PROPOSER_ADDR1, 7);
        assert!(index == 0, 8);
        assert!(group == 0, 9);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_timelock_view_functions(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        assert!(mcms::timelock_min_delay() == 0);
        assert!(mcms::timelock_get_blocked_functions_count() == 0);

        mcms::test_timelock_block_function(
            TEST_TARGET_ADDRESS,
            string::utf8(b"test_module"),
            string::utf8(b"test_function")
        );

        assert!(mcms::timelock_get_blocked_functions_count() == 1);

        let blocked_fn = mcms::timelock_get_blocked_function(0);
        assert!(mcms::target(blocked_fn) == TEST_TARGET_ADDRESS);
        assert!(mcms::module_name(blocked_fn) == string::utf8(b"test_module"));
        assert!(mcms::function_name(blocked_fn) == string::utf8(b"test_function"), 5);

        let new_delay = 10;
        mcms::test_timelock_update_min_delay(new_delay);
        assert!(mcms::timelock_min_delay() == new_delay);

        // Schedule a batch operation and test operation status getters
        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"timelock_update_min_delay")];
        let data = bcs::to_bytes(&MIN_DELAY);
        let datas = vector[data];
        let predecessor = mcms::zero_hash();
        let salt = vector[1u8];
        // Use a delay that is greater than the min_delay to avoid E_INSUFFICIENT_DELAY error
        let delay = 100;

        let calls = mcms::create_calls(targets, module_names, function_names, datas);
        let id = mcms::hash_operation_batch(calls, predecessor, salt);

        assert!(!mcms::timelock_is_operation(id));
        assert!(!mcms::timelock_is_operation_pending(id));
        assert!(!mcms::timelock_is_operation_ready(id)); // Not ready yet due to delay
        assert!(!mcms::timelock_is_operation_done(id));

        let timestamp = mcms::timelock_get_timestamp(id);
        assert!(timestamp == 0);

        mcms::test_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            delay
        );

        assert!(mcms::timelock_is_operation(id));
        assert!(mcms::timelock_is_operation_pending(id));
        assert!(!mcms::timelock_is_operation_ready(id)); // Not ready yet due to delay
        assert!(!mcms::timelock_is_operation_done(id));

        // Get timestamp and verify it's in the future
        let timestamp = mcms::timelock_get_timestamp(id);
        assert!(timestamp > timestamp::now_seconds());

        timestamp::update_global_time_for_test_secs(TIMESTAMP + delay + 100);
        assert!(mcms::timelock_is_operation_ready(id));
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_function_view_functions(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        let target = @0x123;
        let module_name = string::utf8(b"test_module");
        let function_name = string::utf8(b"test_function");

        // Test function helper getters
        let targets = vector[target];
        let module_names = vector[module_name];
        let function_names = vector[function_name];
        let datas = vector[vector[0u8]];

        let calls = mcms::create_calls(targets, module_names, function_names, datas);
        assert!(vector::length(&calls) == 1, 0);

        // Test function view functions
        let data = mcms::data(calls[0]);
        assert!(data == vector[0u8], 1);

        // Test blocked functions view functions
        mcms::test_timelock_block_function(target, module_name, function_name);
        let blocked_fns = mcms::timelock_get_blocked_functions();
        assert!(vector::length(&blocked_fns) == 1, 2);

        // Test function getters on blocked function
        let blocked_fn = blocked_fns[0];
        assert!(mcms::target(blocked_fn) == target, 3);
        assert!(mcms::module_name(blocked_fn) == module_name, 4);
        assert!(mcms::function_name(blocked_fn) == function_name, 5);
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_timelock_dispatch_to_self(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);

        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);

        // mcms::set_config
        let target = @mcms;
        let module_name = string::utf8(b"mcms");
        let function_name = string::utf8(b"set_config");

        let data = bcs::to_bytes(&mcms::proposer_role());
        data.append(
            bcs::to_bytes(&vector[PROPOSER_ADDR1, PROPOSER_ADDR2, PROPOSER_ADDR3])
        );
        data.append(bcs::to_bytes(&SIGNER_GROUPS));
        data.append(bcs::to_bytes(&GROUP_QUORUMS));
        data.append(bcs::to_bytes(&GROUP_PARENTS));
        data.append(bcs::to_bytes(&true));

        mcms::test_timelock_dispatch(target, module_name, function_name, data);

        // timelock_schedule_batch
        let targets = vector[@mcms];
        let module_names = vector[string::utf8(b"mcms")];
        let function_names = vector[string::utf8(b"set_config")];
        let datas = vector[data];
        let predecessor = mcms::zero_hash();
        let salt = vector[1u8];
        let delay = 1;

        dispatch_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            delay
        );

        timestamp::update_global_time_for_test_secs(TIMESTAMP + delay);

        // timelock_execute_batch
        let timelock_execute_batch_data = bcs::to_bytes(&targets);
        timelock_execute_batch_data.append(bcs::to_bytes(&module_names));
        timelock_execute_batch_data.append(bcs::to_bytes(&function_names));
        timelock_execute_batch_data.append(bcs::to_bytes(&datas));
        timelock_execute_batch_data.append(bcs::to_bytes(&predecessor));
        timelock_execute_batch_data.append(bcs::to_bytes(&salt));
        mcms::test_timelock_dispatch(
            target,
            string::utf8(b"mcms"),
            string::utf8(b"timelock_execute_batch"),
            timelock_execute_batch_data
        );

        // timelock_bypasser_execute_batch
        let bypasser_execute_batch_data = bcs::to_bytes(&targets);
        bypasser_execute_batch_data.append(bcs::to_bytes(&module_names));
        bypasser_execute_batch_data.append(bcs::to_bytes(&function_names));
        bypasser_execute_batch_data.append(bcs::to_bytes(&datas));

        mcms::test_timelock_dispatch(
            target,
            string::utf8(b"mcms"),
            string::utf8(b"timelock_bypasser_execute_batch"),
            bypasser_execute_batch_data
        );

        // test_timelock_cancel
        // First schedule the operation for `set_config`
        let salt = vector[2u8];
        dispatch_timelock_schedule_batch(
            targets,
            module_names,
            function_names,
            datas,
            predecessor,
            salt,
            delay
        );
        // Create calls for set_config
        let calls = mcms::create_calls(targets, module_names, function_names, datas);
        let id = mcms::hash_operation_batch(calls, predecessor, salt);
        let timelock_cancel_data = bcs::to_bytes(&id);
        mcms::test_timelock_dispatch(
            target,
            string::utf8(b"mcms"),
            string::utf8(b"timelock_cancel"),
            timelock_cancel_data
        );

        dispatch_timelock_schedule_batch(
            vector[@mcms],
            vector[string::utf8(b"mcms")],
            vector[string::utf8(b"timelock_update_min_delay")],
            vector[bcs::to_bytes(&100)],
            mcms::zero_hash(), // predecessor
            vector[1u8], // salt
            delay // delay
        );
        let new_delay = 2;
        mcms::test_timelock_dispatch(
            target,
            string::utf8(b"mcms"),
            string::utf8(b"timelock_update_min_delay"),
            bcs::to_bytes(&new_delay)
        );

        let data = bcs::to_bytes(&@mcms);
        data.append(bcs::to_bytes(&string::utf8(b"mcms")));
        data.append(bcs::to_bytes(&string::utf8(b"timelock_update_min_delay")));
        dispatch_timelock_schedule_batch(
            vector[@mcms],
            vector[string::utf8(b"mcms")],
            vector[string::utf8(b"timelock_block_function")],
            vector[data],
            mcms::zero_hash(), // predecessor
            vector[1u8], // salt
            new_delay // delay
        );
        mcms::test_timelock_dispatch(
            target,
            string::utf8(b"mcms"),
            string::utf8(b"timelock_block_function"),
            data
        );

        dispatch_timelock_schedule_batch(
            vector[@mcms],
            vector[string::utf8(b"mcms")],
            vector[string::utf8(b"timelock_unblock_function")],
            vector[data],
            mcms::zero_hash(), // predecessor
            vector[1u8], // salt
            new_delay // delay
        );
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms"),
            string::utf8(b"timelock_unblock_function"),
            data
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = 327682, location = mcms::mcms_account)]
    public fun test_timelock_dispatch_to_account(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);

        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_account"),
            string::utf8(b"transfer_ownership"),
            bcs::to_bytes(&@0x123)
        );
        // Fail with E_MUST_BE_PROPOSED_OWNER
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_account"),
            string::utf8(b"accept_ownership"),
            vector[]
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = 196608, location = std::code)]
    public fun test_timelock_dispatch_to_deployer(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);
        mcms_registry::init_module_for_testing(deployer);

        let (metadata, code) = object_code_util::test_metadata_and_code();
        let code_indices: vector<u16> = vector[0, 1];

        // Serialize data for code indices and code chunks
        let data = bcs::to_bytes(&metadata);
        data.append(bcs::to_bytes(&code_indices));
        data.append(bcs::to_bytes(&code));

        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_deployer"),
            string::utf8(b"stage_code_chunk"),
            data
        );

        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_deployer"),
            string::utf8(b"cleanup_staging_area"),
            vector[]
        );

        // Serialize data for stage_code_chunk_and_publish_to_object
        let code_indices: vector<u16> = vector[0, 1];
        let new_owner_seed = vector[1u8];
        let data = bcs::to_bytes(&metadata);
        data.append(bcs::to_bytes(&code_indices));
        data.append(bcs::to_bytes(&code));
        data.append(bcs::to_bytes(&new_owner_seed));

        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_deployer"),
            string::utf8(b"stage_code_chunk_and_publish_to_object"),
            data
        );

        // upgrade
        let object_address = mcms_registry::get_new_code_object_address(new_owner_seed);
        let upgrade_data = bcs::to_bytes(&metadata);
        upgrade_data.append(bcs::to_bytes(&code_indices));
        upgrade_data.append(bcs::to_bytes(&code));
        upgrade_data.append(bcs::to_bytes(&object_address));

        // Will throw `const EALREADY_REQUESTED: u64 = 0x03_0000` from code.rs as we this creates
        // a second publish request in the same TX
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_deployer"),
            string::utf8(b"stage_code_chunk_and_upgrade_object_code"),
            upgrade_data
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_timelock_dispatch_to_registry(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);
        mcms_registry::init_module_for_testing(deployer);

        let (metadata, code) = object_code_util::test_metadata_and_code();
        let object_address =
            object_code_util::publish_code_object(deployer, metadata, code);
        let data = bcs::to_bytes(&object_address);
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_registry"),
            string::utf8(b"create_owner_for_preexisting_code_object"),
            data
        );

        let registered_owner_address =
            mcms_registry::get_registered_owner_address(object_address);
        let expected_owner_address =
            mcms_registry::get_preexisting_code_object_owner_address(object_address);
        assert!(registered_owner_address == expected_owner_address);

        // Transfer code ownership to registered owner
        object::transfer(
            deployer,
            object::address_to_object<PackageRegistry>(object_address),
            registered_owner_address
        );

        // Serialize transfer_code_object
        let data = bcs::to_bytes(&object_address);
        let new_owner_address = signer::address_of(owner);
        data.append(bcs::to_bytes(&new_owner_address));
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_registry"),
            string::utf8(b"transfer_code_object"),
            data
        );

        mcms_registry::accept_code_object(owner, object_address);

        // Serialize execute_code_object_transfer
        let data = bcs::to_bytes(&object_address);
        data.append(bcs::to_bytes(&new_owner_address));
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_registry"),
            string::utf8(b"execute_code_object_transfer"),
            data
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    public fun test_timelock_dispatch_to_registry_accept_code_object(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);
        mcms_registry::init_module_for_testing(deployer);

        let (metadata, code) = object_code_util::test_metadata_and_code();
        let object_address =
            object_code_util::publish_code_object(deployer, metadata, code);
        let data = bcs::to_bytes(&object_address);
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_registry"),
            string::utf8(b"create_owner_for_preexisting_code_object"),
            data
        );

        let registered_owner_address =
            mcms_registry::get_registered_owner_address(object_address);
        let expected_owner_address =
            mcms_registry::get_preexisting_code_object_owner_address(object_address);
        assert!(registered_owner_address == expected_owner_address);

        let code_object = object::address_to_object<PackageRegistry>(object_address);
        // Transfer code ownership to registered owner
        object::transfer(deployer, code_object, registered_owner_address);

        // Serialize transfer_code_object
        let data = bcs::to_bytes(&object_address);
        let new_owner_address = signer::address_of(owner);
        data.append(bcs::to_bytes(&new_owner_address));

        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_registry"),
            string::utf8(b"transfer_code_object"),
            data
        );

        mcms_registry::accept_code_object(owner, object_address);
        // Serialize execute_code_object_transfer
        let data = bcs::to_bytes(&object_address);
        data.append(bcs::to_bytes(&new_owner_address));
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_registry"),
            string::utf8(b"execute_code_object_transfer"),
            data
        );

        assert!(object::owner(code_object) == new_owner_address);
        // Check that the original owner is kept the same, this is needed as we
        // keep the signer_cap for the original owner
        assert!(
            mcms_registry::get_registered_owner_address(object_address)
                == registered_owner_address
        );
        // Check that the code object is owned by the new owner (not MCMS owned)
        assert!(!mcms_registry::is_owned_code_object(object_address));
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[
        expected_failure(
            abort_code = mcms::mcms::E_UNKNOWN_MCMS_REGISTRY_MODULE_FUNCTION,
            location = mcms::mcms
        )
    ]
    public fun test_timelock_dispatch_to_registry_invalid_module(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms_account::transfer_ownership_to_self(owner);
        mcms_account::accept_ownership(deployer);
        mcms_registry::init_module_for_testing(deployer);

        let (metadata, code) = object_code_util::test_metadata_and_code();
        let object_address =
            object_code_util::publish_code_object(deployer, metadata, code);
        let data = bcs::to_bytes(&object_address);
        mcms::test_timelock_dispatch(
            @mcms,
            string::utf8(b"mcms_registry"),
            string::utf8(b"invalid_module_function"),
            data
        );
    }

    #[test(deployer = @mcms, owner = @mcms_owner, framework = @aptos_framework)]
    #[expected_failure(abort_code = mcms::mcms::E_INVALID_ROLE, location = mcms::mcms)]
    public fun test_invalid_role(
        deployer: &signer, owner: &signer, framework: &signer
    ) {
        setup(deployer, owner, framework);
        mcms::multisig_object(100);
    }

    #[test_only]
    public fun dispatch_timelock_schedule_batch(
        targets: vector<address>,
        module_names: vector<String>,
        function_names: vector<String>,
        datas: vector<vector<u8>>,
        predecessor: vector<u8>,
        salt: vector<u8>,
        delay: u64
    ) {
        let schedule_batch_data = bcs::to_bytes(&targets);
        schedule_batch_data.append(bcs::to_bytes(&module_names));
        schedule_batch_data.append(bcs::to_bytes(&function_names));
        schedule_batch_data.append(bcs::to_bytes(&datas));
        schedule_batch_data.append(bcs::to_bytes(&predecessor));
        schedule_batch_data.append(bcs::to_bytes(&salt));
        schedule_batch_data.append(bcs::to_bytes(&delay));

        mcms::test_timelock_dispatch(
            targets[0],
            string::utf8(b"mcms"),
            string::utf8(b"timelock_schedule_batch"),
            schedule_batch_data
        );
    }
}
