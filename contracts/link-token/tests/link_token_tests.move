#[test_only]
module link::link_tests {
    use std::signer;
    use std::string::{Self};
    use std::option::{Self, Option};
    use std::account;
    use std::primary_fungible_store;
    use std::fungible_asset;
    use std::object_code_deployment;

    use mcms::mcms_account;
    use mcms::mcms_registry;
    use link::link_token::{Self};

    const MAX_SUPPLY: u128 = 1000000;
    const DECIMALS: u8 = 8;
    const ICON: vector<u8> = b"http://chainlink.com/link-icon.png";
    const PROJECT: vector<u8> = b"ChainLink Project";

    #[test_only]
    public fun setup(owner: &signer, link: &signer) {
        account::create_account_for_test(signer::address_of(owner));
        account::create_account_for_test(signer::address_of(link));

        mcms_registry::init_module_for_testing(owner);
        mcms_account::init_module_for_testing(owner);

        let (metadata, code) = get_metadata_and_code();
        object_code_deployment::publish(owner, metadata, code);

        link_token::init_module_for_testing(link);
    }

    #[test_only]
    public fun initialize_link(owner: &signer, max_supply: Option<u128>) {
        link_token::initialize(
            owner,
            max_supply,
            DECIMALS,
            string::utf8(ICON),
            string::utf8(PROJECT)
        );
    }

    #[test(owner = @mcms, link = @link)]
    public fun test_initialize_link(owner: &signer, link: &signer) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let metadata_obj = link_token::metadata();
        assert!(fungible_asset::name(metadata_obj) == link_token::name());
        assert!(fungible_asset::symbol(metadata_obj) == link_token::symbol());
        assert!(fungible_asset::decimals(metadata_obj) == DECIMALS);
    }

    #[test(owner = @mcms, recipient = @0xcafe, link = @link)]
    public fun test_mint_link(
        owner: &signer, recipient: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let recipient_addr = signer::address_of(recipient);

        let mint_amount: u64 = 100;
        link_token::mint(owner, recipient_addr, mint_amount);

        let metadata_obj = link_token::metadata();
        assert!(
            primary_fungible_store::balance(recipient_addr, metadata_obj) == mint_amount
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
            abort_code = link::link_token::E_NOT_OWNER, location = link::link_token
        )
    ]
    public fun test_unauthorized_mint(
        owner: &signer, user: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        // Attempt unauthorized mint (should fail)
        link_token::mint(user, signer::address_of(user), 1000000);
    }

    #[test(
        owner = @mcms, recipient1 = @0xcafe, recipient2 = @0xface, link = @link
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
        link_token::mint(owner, recipient1_addr, mint_amount);

        let metadata_obj = link_token::metadata();
        let sender_store =
            primary_fungible_store::ensure_primary_store_exists(
                recipient1_addr, metadata_obj
            );
        let receiver_store =
            primary_fungible_store::ensure_primary_store_exists(
                recipient2_addr, metadata_obj
            );

        let transfer_amount = 500000;
        fungible_asset::transfer(
            recipient1,
            sender_store,
            receiver_store,
            transfer_amount
        );

        assert!(
            primary_fungible_store::balance(recipient1_addr, metadata_obj)
                == mint_amount - transfer_amount
        );
        assert!(
            primary_fungible_store::balance(recipient2_addr, metadata_obj)
                == transfer_amount
        );
    }

    #[test(owner = @mcms, link = @link)]
    public fun test_initialize_with_max_supply(
        owner: &signer, link: &signer
    ) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        let metadata_obj = link_token::metadata();
        assert!(fungible_asset::maximum(metadata_obj) == option::some(MAX_SUPPLY));
    }

    #[test(owner = @mcms, link = @link)]
    #[expected_failure(abort_code = 524289, location = std::object)]
    public fun test_double_initialization(owner: &signer, link: &signer) {
        setup(owner, link);

        initialize_link(owner, option::some(MAX_SUPPLY));

        // Second initialization (should fail): error::already_exists(EOBJECT_EXISTS))
        initialize_link(owner, option::some(MAX_SUPPLY));
    }

    #[test_only]
    fun get_metadata_and_code(): (vector<u8>, vector<vector<u8>>) {
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
