#[test_only]
module link::link_tests {
    use std::account;
    use std::fungible_asset::Self;
    use std::object::{Self, Object};
    use std::object_code_deployment;
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::Self;

    use link::link_token::{Self, TokenState};
    use mcms::mcms_account;
    use mcms::mcms_registry;

    const MAX_SUPPLY: u128 = 1000000;
    const DECIMALS: u8 = 8;
    const ICON: vector<u8> = b"http://chainlink.com/link-icon.png";
    const PROJECT: vector<u8> = b"ChainLink Project";
    const NAME: vector<u8> = b"ChainLink Token";
    const SYMBOL: vector<u8> = b"LINK";

    #[test_only]
    public fun setup(owner: &signer, link: &signer) {
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(link));

        mcms_registry::init_module_for_testing(owner);
        mcms_account::init_module_for_testing(owner);

        let (metadata, code) = test_metadata_and_code();
        object_code_deployment::publish(owner, metadata, code);

        link_token::init_module_for_testing(link);
    }

    #[test_only]
    public fun setup_minters_burners(
        owner: &signer,
        token_state_obj: Object<TokenState>,
        minter: &signer,
        burner: &signer
    ) {
        link_token::apply_allowed_minter_updates(
            owner,
            token_state_obj,
            vector[],
            vector[signer::address_of(minter)]
        );
        link_token::apply_allowed_burner_updates(
            owner,
            token_state_obj,
            vector[],
            vector[signer::address_of(burner)]
        );
    }

    #[test_only]
    public fun initialize_link(owner: &signer, max_supply: Option<u128>) {
        link_token::initialize(
            owner,
            max_supply,
            string::utf8(NAME),
            string::utf8(SYMBOL),
            DECIMALS,
            string::utf8(ICON),
            string::utf8(PROJECT)
        );
    }

    #[test(owner = @mcms, link = @link)]
    public fun test_initialize_link(owner: &signer, link: &signer) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let metadata_obj = token_state_object(owner);
        assert!(fungible_asset::name(metadata_obj) == string::utf8(NAME));
        assert!(fungible_asset::symbol(metadata_obj) == string::utf8(SYMBOL));
        assert!(fungible_asset::decimals(metadata_obj) == DECIMALS);
    }

    #[test(owner = @mcms, recipient = @0xcafe, link = @link)]
    public fun test_mint_link(
        owner: &signer, recipient: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let recipient_addr = signer::address_of(recipient);
        let metadata_obj = token_state_object(owner);

        let mint_amount: u64 = 100;
        let token_state_obj = token_state_object(owner);

        setup_minters_burners(owner, token_state_obj, owner, owner);

        link_token::mint(
            owner,
            token_state_obj,
            recipient_addr,
            mint_amount
        );

        assert!(fungible_asset::supply(metadata_obj)
            == option::some(mint_amount as u128));
        assert!(
            primary_fungible_store::balance(recipient_addr, metadata_obj) == mint_amount
        );
    }

    #[test(owner = @mcms, recipient = @0xcafe, link = @link)]
    public fun test_burn_link(
        owner: &signer, recipient: &signer, link: &signer
    ) {
        // Setup env and mint link first, mint 100 to recipient
        test_mint_link(owner, recipient, link);

        let token_state_obj = token_state_object(owner);

        let recipient_addr = signer::address_of(recipient);
        let burn_amount: u64 = 50;

        link_token::burn(
            owner,
            token_state_obj,
            recipient_addr,
            burn_amount
        );

        // 100 is the mint amount, 50 is the burn amount
        let mint_amount: u64 = 100;
        assert!(
            primary_fungible_store::balance(recipient_addr, token_state_obj)
                == mint_amount - burn_amount
        );

        // Assert tokens are burned from existing supply
        assert!(
            fungible_asset::supply(token_state_obj)
                == option::some((mint_amount - burn_amount) as u128)
        );
    }

    #[test(owner = @mcms, user = @0xface, link = @link)]
    #[
        expected_failure(
            abort_code = link::link_token::E_NOT_OWNER, location = link::link_token
        )
    ]
    public fun test_unauthorized_initialize(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);

        // Attempt unauthorized initialize (should fail)
        initialize_link(user, option::some(MAX_SUPPLY));
    }

    #[test(owner = @mcms, user = @0xface, link = @link)]
    #[
        expected_failure(
            abort_code = link::link_token::E_NOT_ALLOWED_MINTER,
            location = link::link_token
        )
    ]
    public fun test_unauthorized_mint(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let token_state_obj = token_state_object(owner);

        // Attempt unauthorized mint (should fail)
        link_token::mint(
            user,
            token_state_obj,
            signer::address_of(user),
            1000000
        );
    }

    #[test(owner = @mcms, user = @0xface, link = @link)]
    #[
        expected_failure(
            abort_code = link::link_token::E_NOT_ALLOWED_BURNER,
            location = link::link_token
        )
    ]
    public fun test_unauthorized_burn(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let token_state_obj = token_state_object(owner);

        // Attempt unauthorized burn (should fail)
        link_token::burn(
            user,
            token_state_obj,
            signer::address_of(user),
            1000000
        );
    }

    #[test(
        owner = @mcms, recipient1 = @0xface, recipient2 = @0xbeef, link = @link
    )]
    public fun test_token_transfer(
        owner: &signer,
        recipient1: &signer,
        recipient2: &signer,
        link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let recipient1_addr = signer::address_of(recipient1);
        let recipient2_addr = signer::address_of(recipient2);

        let mint_amount = 1000000;
        let token_state_obj = token_state_object(owner);

        setup_minters_burners(owner, token_state_obj, owner, owner);

        link_token::mint(
            owner,
            token_state_obj,
            recipient1_addr,
            mint_amount
        );

        let sender_store =
            primary_fungible_store::ensure_primary_store_exists(
                recipient1_addr, token_state_obj
            );
        let receiver_store =
            primary_fungible_store::ensure_primary_store_exists(
                recipient2_addr, token_state_obj
            );

        let transfer_amount = 500000;
        fungible_asset::transfer(
            recipient1,
            sender_store,
            receiver_store,
            transfer_amount
        );

        assert!(
            primary_fungible_store::balance(recipient1_addr, token_state_obj)
                == mint_amount - transfer_amount
        );
        assert!(
            primary_fungible_store::balance(recipient2_addr, token_state_obj)
                == transfer_amount
        );
    }

    #[test(owner = @mcms, link = @link)]
    public fun test_initialize_with_max_supply(
        owner: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let metadata_obj = token_state_object(owner);
        assert!(fungible_asset::maximum(metadata_obj) == option::some(MAX_SUPPLY));
    }

    #[test(owner = @mcms, link = @link)]
    public fun test_can_initialize_with_different_symbol(
        owner: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        // This is allowed because the owner is different
        link_token::initialize(
            owner,
            option::none(),
            string::utf8(NAME),
            string::utf8(b"USDC"),
            DECIMALS,
            string::utf8(ICON),
            string::utf8(PROJECT)
        );
    }

    #[test(owner = @mcms, link = @link)]
    #[expected_failure(abort_code = 524289, location = std::object)]
    public fun test_initialize_with_same_symbol_fails(
        owner: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        // Second initialization (should fail): error::already_exists(EOBJECT_EXISTS))
        initialize_link(owner, option::some(MAX_SUPPLY));
    }

    #[test(owner = @mcms, new_owner = @0xface, link = @link)]
    public fun test_ownership_transfer_flow(
        owner: &signer, new_owner: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));
        let token_state_obj = token_state_object(owner);

        let owner_addr = signer::address_of(owner);
        let new_owner_addr = signer::address_of(new_owner);

        // Verify initial owner
        assert!(link_token::owner(token_state_obj) == owner_addr, 0);

        // Step 1: Owner requests transfer of ownership to new_owner
        link_token::transfer_ownership(owner, token_state_obj, new_owner_addr);

        // Ownership should still be with the original owner
        assert!(link_token::owner(token_state_obj) == owner_addr, 0);

        // Step 2: New owner accepts the ownership
        link_token::accept_ownership(new_owner, token_state_obj);

        // Ownership should still be with the original owner until execution
        assert!(link_token::owner(token_state_obj) == owner_addr, 0);

        // Step 3: Original owner executes the transfer
        link_token::execute_ownership_transfer(owner, token_state_obj, new_owner_addr);

        // Verify that ownership has been transferred
        assert!(link_token::owner(token_state_obj) == new_owner_addr, 0);
    }

    #[test(owner = @mcms, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    public fun test_unauthorized_transfer_ownership(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));
        let token_state_obj = token_state_object(owner);

        // User attempts to transfer ownership (should fail) E_ONLY_CALLABLE_BY_OWNER
        link_token::transfer_ownership(user, token_state_obj, @0xbeef);
    }

    #[test(
        owner = @mcms, user = @0xface, other = @0xbeef, link = @link
    )]
    #[expected_failure(abort_code = 327681, location = ccip::ownable)]
    public fun test_wrong_account_accept_ownership(
        owner: &signer,
        user: &signer,
        other: &signer,
        link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));
        let token_state_obj = token_state_object(owner);

        // Owner requests transfer to user
        link_token::transfer_ownership(owner, token_state_obj, signer::address_of(user));

        // Other account tries to accept (should fail) E_MUST_BE_PROPOSED_OWNER
        link_token::accept_ownership(other, token_state_obj);
    }

    #[test(owner = @mcms, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 327686, location = ccip::ownable)]
    public fun test_accept_ownership_without_transfer(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));
        let token_state_obj = token_state_object(owner);

        // User tries to accept ownership without a pending transfer (should fail) E_NO_PENDING_TRANSFER
        link_token::accept_ownership(user, token_state_obj);
    }

    #[test(owner = @mcms, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 196615, location = ccip::ownable)]
    public fun test_execute_transfer_without_acceptance(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));
        let token_state_obj = token_state_object(owner);

        // Owner initiates transfer
        let user_addr = signer::address_of(user);
        link_token::transfer_ownership(owner, token_state_obj, user_addr);

        // Owner tries to execute transfer before user accepts (should fail) E_TRANSFER_NOT_ACCEPTED
        link_token::execute_ownership_transfer(owner, token_state_obj, user_addr);
    }

    #[test(
        owner = @mcms, user = @0xface, other = @0xbeef, link = @link
    )]
    #[expected_failure(abort_code = 327684, location = ccip::ownable)]
    public fun test_execute_transfer_to_wrong_address(
        owner: &signer,
        user: &signer,
        other: &signer,
        link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));
        let token_state_obj = token_state_object(owner);

        // Owner initiates transfer to user
        let user_addr = signer::address_of(user);
        link_token::transfer_ownership(owner, token_state_obj, user_addr);

        // User accepts
        link_token::accept_ownership(user, token_state_obj);

        // Owner tries to execute transfer to a different address (should fail) E_PROPOSED_OWNER_MISMATCH
        link_token::execute_ownership_transfer(
            owner, token_state_obj, signer::address_of(other)
        );
    }

    #[test(owner = @mcms, user = @0xface, link = @link)]
    #[expected_failure(abort_code = 327683, location = ccip::ownable)]
    public fun test_unauthorized_execute_transfer(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);
        initialize_link(owner, option::some(MAX_SUPPLY));
        let token_state_obj = token_state_object(owner);

        // Owner initiates transfer
        let user_addr = signer::address_of(user);
        link_token::transfer_ownership(owner, token_state_obj, user_addr);

        // User accepts
        link_token::accept_ownership(user, token_state_obj);

        // User tries to execute the transfer (should fail, only owner can execute) E_ONLY_CALLABLE_BY_OWNER
        link_token::execute_ownership_transfer(user, token_state_obj, user_addr);
    }

    #[test_only]
    public fun metadata_addr(owner: &signer): address {
        object::create_object_address(&signer::address_of(owner), SYMBOL)
    }

    #[test_only]
    public fun token_state_object(owner: &signer): Object<TokenState> {
        object::address_to_object<TokenState>(metadata_addr(owner))
    }

    #[test_only]
    /// Mock metadata and code for testing
    fun test_metadata_and_code(): (vector<u8>, vector<vector<u8>>) {

        /*
        [dev-addresses]
        mock = "0x100"

        module mock::mock {

            fun init_module(publisher: &signer) {}

            #[test_only]
            public fun init_module_for_testing(publisher: &signer) {
                init_module(publisher);
            }
        }
        */

        // Metadata vector<u8>
        let metadata = vector[
            4u8, 77u8, 111u8, 99u8, 107u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            64u8, 66u8, 52u8, 56u8, 55u8, 68u8, 48u8, 69u8, 65u8, 54u8, 56u8, 56u8, 49u8,
            48u8, 50u8, 53u8, 49u8, 48u8, 51u8, 52u8, 67u8, 66u8, 49u8, 50u8, 48u8, 66u8,
            70u8, 56u8, 68u8, 52u8, 56u8, 66u8, 52u8, 54u8, 68u8, 68u8, 49u8, 68u8, 65u8,
            55u8, 49u8, 54u8, 54u8, 66u8, 53u8, 51u8, 68u8, 67u8, 52u8, 50u8, 52u8, 51u8,
            49u8, 55u8, 56u8, 57u8, 54u8, 57u8, 50u8, 56u8, 69u8, 48u8, 56u8, 66u8, 53u8,
            118u8, 31u8, 139u8, 8u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 255u8, 109u8, 203u8,
            65u8, 10u8, 128u8, 32u8, 16u8, 133u8, 225u8, 253u8, 156u8, 34u8, 220u8, 23u8,
            211u8, 1u8, 58u8, 66u8, 39u8, 16u8, 137u8, 65u8, 135u8, 138u8, 72u8, 197u8,
            41u8, 233u8, 248u8, 41u8, 174u8, 130u8, 182u8, 223u8, 255u8, 158u8, 142u8,
            100u8, 15u8, 90u8, 217u8, 128u8, 167u8, 147u8, 187u8, 169u8, 83u8, 115u8,
            176u8, 135u8, 130u8, 204u8, 73u8, 246u8, 224u8, 43u8, 140u8, 3u8, 14u8, 168u8,
            128u8, 238u8, 107u8, 11u8, 73u8, 138u8, 104u8, 3u8, 160u8, 201u8, 185u8, 196u8,
            34u8, 44u8, 6u8, 206u8, 242u8, 168u8, 195u8, 69u8, 21u8, 119u8, 156u8, 251u8,
            159u8, 134u8, 207u8, 136u8, 216u8, 122u8, 100u8, 239u8, 216u8, 219u8, 189u8,
            230u8, 182u8, 255u8, 218u8, 11u8, 110u8, 36u8, 72u8, 12u8, 147u8, 0u8, 0u8,
            0u8, 1u8, 4u8, 109u8, 111u8, 99u8, 107u8, 124u8, 31u8, 139u8, 8u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 2u8, 255u8, 109u8, 141u8, 75u8, 10u8, 128u8, 48u8, 12u8, 68u8,
            247u8, 61u8, 69u8, 64u8, 16u8, 189u8, 66u8, 61u8, 138u8, 72u8, 65u8, 173u8,
            26u8, 108u8, 83u8, 233u8, 103u8, 33u8, 210u8, 187u8, 107u8, 227u8, 78u8, 156u8,
            69u8, 22u8, 153u8, 55u8, 51u8, 214u8, 205u8, 201u8, 104u8, 176u8, 110u8, 218u8,
            165u8, 44u8, 23u8, 46u8, 33u8, 224u8, 209u8, 146u8, 8u8, 144u8, 48u8, 42u8,
            203u8, 68u8, 115u8, 164u8, 209u8, 96u8, 216u8, 180u8, 151u8, 80u8, 7u8, 92u8,
            73u8, 251u8, 22u8, 174u8, 252u8, 178u8, 85u8, 31u8, 117u8, 136u8, 202u8, 145u8,
            57u8, 7u8, 126u8, 48u8, 60u8, 125u8, 59u8, 212u8, 226u8, 188u8, 42u8, 36u8,
            210u8, 250u8, 223u8, 199u8, 225u8, 162u8, 223u8, 229u8, 182u8, 99u8, 63u8,
            139u8, 44u8, 110u8, 245u8, 55u8, 15u8, 186u8, 183u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8
        ];

        // Code vector<vector<u8>>
        let code = vector[
            vector[
                161u8, 28u8, 235u8, 11u8, 7u8, 0u8, 0u8, 10u8, 7u8, 1u8, 0u8, 2u8, 3u8,
                2u8, 6u8, 5u8, 8u8, 4u8, 7u8, 12u8, 17u8, 8u8, 29u8, 32u8, 16u8, 61u8,
                31u8, 12u8, 92u8, 10u8, 0u8, 0u8, 0u8, 1u8, 0u8, 1u8, 0u8, 1u8, 1u8, 6u8,
                12u8, 0u8, 4u8, 109u8, 111u8, 99u8, 107u8, 11u8, 105u8, 110u8, 105u8,
                116u8, 95u8, 109u8, 111u8, 100u8, 117u8, 108u8, 101u8, 0u8, 0u8, 0u8, 0u8,
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 17u8, 20u8,
                99u8, 111u8, 109u8, 112u8, 105u8, 108u8, 97u8, 116u8, 105u8, 111u8, 110u8,
                95u8, 109u8, 101u8, 116u8, 97u8, 100u8, 97u8, 116u8, 97u8, 9u8, 0u8, 3u8,
                50u8, 46u8, 48u8, 3u8, 50u8, 46u8, 49u8, 0u8, 0u8, 0u8, 0u8, 1u8, 3u8
            ],
            vector[11u8, 0u8, 1u8, 2u8, 0u8]
        ];

        return (metadata, code)
    }
}
