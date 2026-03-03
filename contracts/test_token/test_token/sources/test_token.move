module test_token::test_token {
    use std::event;
    use std::error;
    use std::fungible_asset::{Self, BurnRef, Metadata, MintRef, TransferRef};
    use std::object::{
        Self,
        ExtendRef,
        Object,
        TransferRef as ObjectTransferRef,
        ObjectCore
    };
    use std::option;
    use std::option::{Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::function_info;
    use aptos_framework::fungible_asset::FungibleAsset;

    const TOKEN_STATE_SEED: vector<u8> = b"test_token::test_token::token_state";

    struct TokenStateDeployment has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenState has key {
        extend_ref: ExtendRef,
        transfer_ref: ObjectTransferRef,
        token: Object<Metadata>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct TokenMetadataRefs has key {
        extend_ref: ExtendRef,
        mint_ref: MintRef,
        burn_ref: BurnRef,
        transfer_ref: TransferRef,
        additional_mint_ref: Option<MintRef>,
        additional_burn_ref: Option<BurnRef>,
        additional_transfer_ref: Option<TransferRef>
    }

    #[event]
    struct Initialize has drop, store {
        publisher: address,
        token: Object<Metadata>,
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

    #[event]
    struct Burn has drop, store {
        burner: address,
        from: address,
        amount: u64
    }

    const E_NOT_PUBLISHER: u64 = 1;
    const E_NOT_ALLOWED_MINTER: u64 = 2;
    const E_NOT_ALLOWED_BURNER: u64 = 3;
    const E_TOKEN_NOT_INITIALIZED: u64 = 4;
    const E_TOKEN_ALREADY_INITIALIZED: u64 = 5;
    const E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED: u64 = 6;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"TestToken 1.0.0")
    }

    #[view]
    public fun token_state_address(): address {
        token_state_address_internal()
    }

    inline fun token_state_address_internal(): address {
        object::create_object_address(&@test_token, TOKEN_STATE_SEED)
    }

    #[view]
    public fun token_metadata(): address acquires TokenState {
        assert!(
            exists<TokenState>(token_state_address_internal()),
            E_TOKEN_NOT_INITIALIZED
        );
        token_metadata_internal(&TokenState[token_state_address_internal()])
    }

    inline fun token_metadata_internal(state: &TokenState): address {
        object::object_address(&state.token)
    }

    /// `publisher` is the code object, deployed through object_code_deployment
    fun init_module(publisher: &signer) {
        assert!(object::is_object(@test_token), E_NOT_PUBLISHER);

        // Create object owned by code object
        let constructor_ref = &object::create_named_object(publisher, TOKEN_STATE_SEED);
        let extend_ref = object::generate_extend_ref(constructor_ref);
        let token_state_signer = &object::generate_signer(constructor_ref);

        move_to(
            token_state_signer,
            TokenStateDeployment {
                extend_ref,
                transfer_ref: object::generate_transfer_ref(constructor_ref)
            }
        );
    }

    public entry fun initialize(
        publisher: &signer,
        max_supply: Option<u128>,
        name: String,
        symbol: String,
        decimals: u8,
        icon: String,
        project: String,
        enable_dispatch_hook: bool
    ) acquires TokenStateDeployment {
        let publisher_addr = signer::address_of(publisher);
        let token_state_address = token_state_address_internal();

        assert!(
            exists<TokenStateDeployment>(token_state_address),
            E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED
        );

        let TokenStateDeployment { extend_ref, transfer_ref } =
            move_from<TokenStateDeployment>(token_state_address);

        let token_state_signer = &object::generate_signer_for_extending(&extend_ref);

        // Code object owns token state, which owns the fungible asset
        // Code object => token state => fungible asset
        let constructor_ref =
            &object::create_named_object(token_state_signer, *symbol.bytes());

        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            max_supply,
            name,
            symbol,
            decimals,
            icon,
            project
        );
        if (enable_dispatch_hook) {
            let deposit =
                function_info::new_function_info_from_address(
                    @test_token,
                    string::utf8(b"test_token"),
                    string::utf8(b"deposit")
                );
            let withdraw =
                function_info::new_function_info_from_address(
                    @test_token,
                    string::utf8(b"test_token"),
                    string::utf8(b"withdraw")
                );
            dispatchable_fungible_asset::register_dispatch_functions(
                constructor_ref,
                option::some(withdraw),
                option::some(deposit),
                option::none()
            )
        };

        let metadata_object_signer = &object::generate_signer(constructor_ref);
        move_to(
            metadata_object_signer,
            TokenMetadataRefs {
                extend_ref: object::generate_extend_ref(constructor_ref),
                mint_ref: fungible_asset::generate_mint_ref(constructor_ref),
                burn_ref: fungible_asset::generate_burn_ref(constructor_ref),
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref),
                additional_mint_ref: option::some(
                    fungible_asset::generate_mint_ref(constructor_ref)
                ),
                additional_burn_ref: option::some(
                    fungible_asset::generate_burn_ref(constructor_ref)
                ),
                additional_transfer_ref: option::some(
                    fungible_asset::generate_transfer_ref(constructor_ref)
                )
            }
        );

        let token = object::object_from_constructor_ref(constructor_ref);

        event::emit(
            Initialize {
                publisher: publisher_addr,
                token,
                max_supply,
                decimals,
                icon,
                project
            }
        );

        move_to(
            token_state_signer,
            TokenState { extend_ref, transfer_ref, token }
        );
    }

    // Hooks
    #[event]
    struct DepositHook has drop, store {
        account: address,
        amount: u64
    }

    public fun deposit<T: key>(
        store: Object<T>, fa: FungibleAsset, transfer_ref: &TransferRef
    ) {
        event::emit(
            DepositHook {
                account: object::owner(store),
                amount: fungible_asset::amount(&fa)
            }
        );

        fungible_asset::deposit_with_ref(transfer_ref, store, fa)
    }

    #[event]
    struct WithdrawHook has drop, store {
        account: address,
        amount: u64
    }

    public fun withdraw<T: key>(
        store: Object<T>, amount: u64, transfer_ref: &TransferRef
    ): FungibleAsset {
        event::emit(WithdrawHook { account: object::owner(store), amount });

        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }

    // ================================================================
    // |                      Mint/Burn Functions                      |
    // ================================================================
    public entry fun mint(
        minter: &signer, to: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        if (amount == 0) { return };

        let minter_addr = signer::address_of(minter);
        let state = &mut TokenState[token_state_address_internal()];

        primary_fungible_store::mint(
            &borrow_token_metadata_refs(state).mint_ref, to, amount
        );

        event::emit(Mint { minter: minter_addr, to, amount });
    }

    public entry fun burn(
        burner: &signer, from: address, amount: u64
    ) acquires TokenMetadataRefs, TokenState {
        if (amount == 0) { return };

        let burner_addr = signer::address_of(burner);
        let state = &mut TokenState[token_state_address_internal()];

        primary_fungible_store::burn(
            &borrow_token_metadata_refs(state).burn_ref, from, amount
        );

        event::emit(Burn { burner: burner_addr, from, amount });
    }

    inline fun borrow_token_metadata_refs(state: &TokenState): &TokenMetadataRefs {
        &TokenMetadataRefs[token_metadata_internal(state)]
    }

    public fun get_additional_mint_ref(
        signer: &signer
    ): MintRef acquires TokenState, TokenMetadataRefs {
        assert_can_get_refs(signer::address_of(signer));

        let state = &TokenState[token_state_address_internal()];
        let ref =
            borrow_global_mut<TokenMetadataRefs>(object::object_address(&state.token)).additional_mint_ref
                .extract();
        ref
    }

    public fun get_additional_burn_ref(
        signer: &signer
    ): BurnRef acquires TokenState, TokenMetadataRefs {
        assert_can_get_refs(signer::address_of(signer));

        let state = &TokenState[token_state_address_internal()];
        let ref =
            borrow_global_mut<TokenMetadataRefs>(object::object_address(&state.token)).additional_burn_ref
                .extract();
        ref
    }

    public fun get_additional_transfer_ref(
        signer: &signer
    ): TransferRef acquires TokenState, TokenMetadataRefs {
        assert_can_get_refs(signer::address_of(signer));

        let state = &TokenState[token_state_address_internal()];
        let ref =
            borrow_global_mut<TokenMetadataRefs>(object::object_address(&state.token)).additional_transfer_ref
                .extract();
        ref
    }

    fun assert_can_get_refs(caller_address: address) {
        if (caller_address == @test_token) { return };

        if (object::is_object(@test_token)) {
            let test_token_object = object::address_to_object<ObjectCore>(@test_token);
            if (caller_address == object::owner(test_token_object)
                || caller_address == object::root_owner(test_token_object)) { return };
        };

        abort error::permission_denied(E_NOT_PUBLISHER)
    }
}
