module ccip_ping_pong_demo::ping_pong_demo {
    use std::account::{Self, SignerCapability};
    use std::error;
    use std::event::{Self, EventHandle};
    use std::fungible_asset::Metadata;
    use std::object::{Self, Object, ObjectCore};
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::signer;
    use std::string::{Self, String};

    use ccip::client;
    use ccip::eth_abi;
    use ccip::ownable;
    use ccip::receiver_registry;

    use ccip_router::router;

    const STORE_OBJECT_SEED: vector<u8> = b"CcipPingPongDemoStore";

    struct PingPongDeployment has key, store {
        store_signer_cap: SignerCapability,
        ping_events: EventHandle<Ping>,
        pong_events: EventHandle<Pong>
    }

    struct PingPongDemo has key, store {
        ownable_state: ownable::OwnableState,
        store_signer_cap: SignerCapability,
        fee_token: Object<Metadata>,
        counterpart_chain_selector: u64,
        counterpart_address: vector<u8>,
        is_paused: bool,
        ping_events: EventHandle<Ping>,
        pong_events: EventHandle<Pong>
    }

    struct PingPongProof has drop {}

    #[event]
    struct Ping has store, drop {
        ping_pong_count: u256
    }

    #[event]
    struct Pong has store, drop {
        ping_pong_count: u256
    }

    const E_NOT_PUBLISHER: u64 = 1;
    const E_INVALID_FEE_TOKEN: u64 = 2;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"PingPongDemo 1.6.0")
    }

    fun init_module(publisher: &signer) {
        receiver_registry::register_receiver(
            publisher, b"ping_pong_demo", PingPongProof {}
        );

        let (_, store_signer_cap) =
            account::create_resource_account(publisher, STORE_OBJECT_SEED);

        move_to(
            publisher,
            PingPongDeployment {
                store_signer_cap,
                ping_events: account::new_event_handle<Ping>(publisher),
                pong_events: account::new_event_handle<Pong>(publisher)
            }
        );
    }

    public fun initialize(
        caller: &signer,
        fee_token_address: address,
        counterpart_chain_selector: u64,
        counterpart_address: vector<u8>
    ) acquires PingPongDeployment {
        assert_can_initialize(signer::address_of(caller));

        let PingPongDeployment { store_signer_cap, ping_events, pong_events } =
            move_from<PingPongDeployment>(@ccip_ping_pong_demo);

        let store_signer = account::create_signer_with_capability(&store_signer_cap);

        assert!(
            object::object_exists<Metadata>(fee_token_address),
            error::invalid_argument(E_INVALID_FEE_TOKEN)
        );
        let fee_token = object::address_to_object<Metadata>(fee_token_address);

        move_to(
            &store_signer,
            PingPongDemo {
                ownable_state: ownable::new(&store_signer, signer::address_of(caller)),
                store_signer_cap,
                fee_token,
                counterpart_chain_selector,
                counterpart_address,
                is_paused: false,
                ping_events,
                pong_events
            }
        );
    }

    #[view]
    public fun get_fee_token(): address acquires PingPongDemo {
        object::object_address(&borrow_state().fee_token)
    }

    #[view]
    public fun is_paused(): bool acquires PingPongDemo {
        borrow_state().is_paused
    }

    #[view]
    public fun get_counterpart_chain_selector(): u64 acquires PingPongDemo {
        borrow_state().counterpart_chain_selector
    }

    #[view]
    public fun get_counterpart_address(): vector<u8> acquires PingPongDemo {
        borrow_state().counterpart_address
    }

    public fun set_counterpart(
        caller: &signer, counterpart_chain_selector: u64, counterpart_address: vector<u8>
    ) acquires PingPongDemo {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        state.counterpart_chain_selector = counterpart_chain_selector;
        state.counterpart_address = counterpart_address;
    }

    public fun set_paused(caller: &signer, is_paused: bool) acquires PingPongDemo {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        state.is_paused = is_paused;
    }

    public fun start_ping_pong(caller: &signer) acquires PingPongDemo {
        let state = borrow_state_mut();
        ownable::assert_only_owner(signer::address_of(caller), &state.ownable_state);

        respond_internal(state, 1);
    }

    inline fun respond_internal(
        state: &mut PingPongDemo, ping_pong_count: u256
    ) {
        if ((ping_pong_count & 1) == 1) {
            event::emit_event(&mut state.ping_events, Ping { ping_pong_count });
        } else {
            event::emit_event(&mut state.pong_events, Pong { ping_pong_count });
        };

        let caller = account::create_signer_with_capability(&state.store_signer_cap);
        let fee_token_store =
            primary_fungible_store::ensure_primary_store_exists(
                signer::address_of(&caller), state.fee_token
            );

        router::ccip_send(
            &caller,
            state.counterpart_chain_selector,
            state.counterpart_address,
            encode_count(ping_pong_count),
            /* token_addresses= */ vector[],
            /* token_amounts= */ vector[],
            /* token_store_addresses= */ vector[],
            object::object_address(&state.fee_token),
            object::object_address(&fee_token_store),
            /* extra_args= */ vector[]
        );
    }

    public fun ccip_receive<T: key>(_metadata: Object<T>): Option<u128> acquires PingPongDemo {
        let state = borrow_state_mut();
        let message =
            receiver_registry::get_receiver_input(@ccip_ping_pong_demo, PingPongProof {});
        let data = client::get_data(&message);
        let count = decode_count(data);
        if (!state.is_paused) {
            respond_internal(state, count + 1);
        };

        option::none()
    }

    #[view]
    public fun get_store_address(): address {
        store_address()
    }

    inline fun store_address(): address {
        account::create_resource_address(&@ccip_ping_pong_demo, STORE_OBJECT_SEED)
    }

    inline fun borrow_state(): &PingPongDemo {
        borrow_global<PingPongDemo>(store_address())
    }

    inline fun borrow_state_mut(): &mut PingPongDemo {
        borrow_global_mut<PingPongDemo>(store_address())
    }

    inline fun encode_count(count: u256): vector<u8> {
        let ret = vector[];
        ccip::eth_abi::encode_u256(&mut ret, count);
        ret
    }

    inline fun decode_count(data: vector<u8>): u256 {
        let stream = eth_abi::new_stream(data);
        eth_abi::decode_u256(&mut stream)
    }

    fun assert_can_initialize(caller_address: address) {
        if (caller_address == @ccip_ping_pong_demo) { return };

        if (object::is_object(@ccip_ping_pong_demo)) {
            let ccip_ping_pong_demo_object =
                object::address_to_object<ObjectCore>(@ccip_ping_pong_demo);
            if (caller_address == object::owner(ccip_ping_pong_demo_object)
                || caller_address == object::root_owner(ccip_ping_pong_demo_object)) {
                return
            };
        };

        abort error::permission_denied(E_NOT_PUBLISHER)
    }

    // ================================================================
    // |                          Ownable                             |
    // ================================================================
    #[view]
    public fun owner(): address acquires PingPongDemo {
        let state = borrow_state();
        ownable::owner(&state.ownable_state)
    }

    #[view]
    public fun has_pending_transfer(): bool acquires PingPongDemo {
        ownable::has_pending_transfer(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_from(): Option<address> acquires PingPongDemo {
        ownable::pending_transfer_from(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_to(): Option<address> acquires PingPongDemo {
        ownable::pending_transfer_to(&borrow_state().ownable_state)
    }

    #[view]
    public fun pending_transfer_accepted(): Option<bool> acquires PingPongDemo {
        ownable::pending_transfer_accepted(&borrow_state().ownable_state)
    }

    public entry fun transfer_ownership(caller: &signer, to: address) acquires PingPongDemo {
        let state = borrow_state_mut();
        ownable::transfer_ownership(caller, &mut state.ownable_state, to)
    }

    public entry fun accept_ownership(caller: &signer) acquires PingPongDemo {
        let state = borrow_state_mut();
        ownable::accept_ownership(caller, &mut state.ownable_state)
    }
}
