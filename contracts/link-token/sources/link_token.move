module link::link_token {
    use std::event;
    use std::fungible_asset::{Self, MintRef, TransferRef, BurnRef, Metadata};
    use std::object::{Self, Object, ExtendRef};
    use std::primary_fungible_store;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};
    use std::code::{PackageRegistry};
    use mcms::bcs_stream;
    use mcms::mcms_registry;

    const NAME: vector<u8> = b"ChainLink Token";
    const SYMBOL: vector<u8> = b"LINK";

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct ManagementRefs has key {
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef
    }

    #[event]
    struct Initialize has drop, store {
        publisher: address,
        max_supply: Option<u128>,
        decimals: u8,
        icon: String,
        project: String
    }

    #[event]
    struct Mint has drop, store {
        minter: address,
        to: address,
        amount: u64
    }

    const E_UNKNOWN_FUNCTION: u64 = 0;
    const E_NOT_OWNER: u64 = 1;
    const E_NOT_PUBLISHER: u64 = 2;

    fun init_module(publisher: &signer) {
        assert!(object::object_exists<PackageRegistry>(@link), E_NOT_PUBLISHER);

        if (@mcms_register_entrypoints != @0x0) {
            mcms_registry::register_entrypoint(
                publisher, string::utf8(b"link_token"), McmsCallback {}
            );
        };
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"LinkToken 1.0.0")
    }

    #[view]
    public fun name(): String {
        string::utf8(NAME)
    }

    #[view]
    public fun symbol(): String {
        string::utf8(SYMBOL)
    }

    #[view]
    public fun link_address(): address {
        let owner = object::owner(code_object());
        object::create_object_address(&owner, SYMBOL)
    }

    #[view]
    public fun metadata(): Object<Metadata> {
        object::address_to_object(link_address())
    }

    public entry fun initialize(
        publisher: &signer,
        max_supply: Option<u128>,
        decimals: u8,
        icon: String,
        project: String
    ) {
        assert_owns_code_object(signer::address_of(publisher));

        let constructor_ref = &object::create_named_object(publisher, SYMBOL);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            max_supply,
            string::utf8(NAME),
            string::utf8(SYMBOL),
            decimals,
            icon,
            project
        );

        let metadata_object_signer = &object::generate_signer(constructor_ref);
        move_to(
            metadata_object_signer,
            ManagementRefs {
                extend_ref: object::generate_extend_ref(constructor_ref),
                mint_ref: fungible_asset::generate_mint_ref(constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(constructor_ref),
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref)
            }
        );

        event::emit(
            Initialize {
                publisher: signer::address_of(publisher),
                max_supply,
                decimals,
                icon,
                project
            }
        );
    }

    /// Mint new tokens to the `to` account.
    public entry fun mint(minter: &signer, to: address, amount: u64) acquires ManagementRefs {
        assert_owns_code_object(signer::address_of(minter));

        if (amount == 0) { return };

        let management = &ManagementRefs[link_address()];
        primary_fungible_store::mint(&management.mint_ref, to, amount);

        event::emit(Mint { minter: signer::address_of(minter), to, amount });
    }

    fun assert_owns_code_object(caller_addr: address) {
        assert!(
            object::owns(code_object(), caller_addr),
            E_NOT_OWNER
        );
    }

    fun code_object(): Object<PackageRegistry> {
        object::address_to_object<PackageRegistry>(@link)
    }

    // ================================================================
    // |                      MCMS Entrypoint                         |
    // ================================================================

    struct McmsCallback has drop {}

    public fun mcms_entrypoint<T: key>(
        _metadata: object::Object<T>
    ): Option<u128> acquires ManagementRefs {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@link, McmsCallback {});

        let function_bytes = *string::bytes(&function);
        let stream = bcs_stream::new(data);

        if (function_bytes == b"initialize") {
            let max_supply =
                bcs_stream::deserialize_option(
                    &mut stream, |stream| bcs_stream::deserialize_u128(stream)
                );
            let decimals = bcs_stream::deserialize_u8(&mut stream);
            let icon = bcs_stream::deserialize_string(&mut stream);
            let project = bcs_stream::deserialize_string(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            initialize(&caller, max_supply, decimals, icon, project)
        } else if (function_bytes == b"mint") {
            let to = bcs_stream::deserialize_address(&mut stream);
            let amount = bcs_stream::deserialize_u64(&mut stream);
            bcs_stream::assert_is_consumed(&stream);

            mint(&caller, to, amount)
        } else {
            abort E_UNKNOWN_FUNCTION
        };

        option::none()
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module(publisher);
    }
}
