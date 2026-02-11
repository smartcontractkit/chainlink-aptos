#[test_only]
/// Compatible with dispatchable and non-dispatchable tokens
/// When transferring tokens, use `primary_fungible_store::transfer` as this triggers the dispatchable fungible asset hook
module ccip_offramp::mock_ccip_receiver {
    use std::account;
    use std::event;
    use std::object::{Self, Object};
    use std::string::{Self, String};
    use std::fungible_asset::{Self, Metadata};
    use std::option::{Self, Option};
    use std::primary_fungible_store;
    use std::from_bcs;
    use std::signer;

    use ccip::client;
    use ccip::receiver_registry;

    #[event]
    struct ReceivedMessage has store, drop {
        message: String
    }

    #[event]
    struct ForwardedTokens has store, drop {
        final_recipient: address
    }

    #[event]
    struct ReceivedTokensOnly has store, drop {
        token_count: u64
    }

    struct CCIPReceiverState has key {
        signer_cap: account::SignerCapability,
        received_message_handle: event::EventHandle<ReceivedMessage>,
        forwarded_tokens_handle: event::EventHandle<ForwardedTokens>,
        received_tokens_only_handle: event::EventHandle<ReceivedTokensOnly>
    }

    const E_RESOURCE_NOT_FOUND_ON_ACCOUNT: u64 = 1;
    const E_UNAUTHORIZED: u64 = 2;
    const E_INVALID_TOKEN_ADDRESS: u64 = 3;
    const E_NO_TOKENS_AVAILABLE_TO_WITHDRAW: u64 = 4;
    /// Test-only abort triggered when message data equals "abort".
    const E_TEST_ABORT: u64 = 5;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"MockCCIPReceiver 1.6.0")
    }

    const MODULE_NAME: vector<u8> = b"mock_ccip_receiver";

    fun init_module(publisher: &signer) {
        // Create a signer capability for the receiver account
        let signer_cap = account::create_test_signer_cap(signer::address_of(publisher));

        // Create a unique handle for each event type
        let received_message_handle =
            account::new_event_handle<ReceivedMessage>(publisher);
        let forwarded_tokens_handle =
            account::new_event_handle<ForwardedTokens>(publisher);
        let received_tokens_only_handle =
            account::new_event_handle<ReceivedTokensOnly>(publisher);

        // Move all state into the single resource struct
        move_to(
            publisher,
            CCIPReceiverState {
                signer_cap,
                received_message_handle,
                forwarded_tokens_handle,
                received_tokens_only_handle
            }
        );

        // Default to V2 registration
        receiver_registry::register_receiver_v2(
            publisher, |message| ccip_receive_v2(message)
        );
    }

    /// Register this receiver as V1 (dispatchable fungible asset mode)
    /// This is used for testing V1 compatibility
    public fun register_as_v1(publisher: &signer) {
        receiver_registry::register_receiver(publisher, MODULE_NAME, CCIPReceiverProof {});
    }

    /// Migrate from V1 to V2 registration
    /// This demonstrates the upgrade path from dispatchable FA to closures
    public fun migrate_to_v2(publisher: &signer) {
        // V2 registration will coexist with V1
        // The dispatcher will prefer V2 when both exist
        receiver_registry::register_receiver_v2(
            publisher, |message| ccip_receive_v2(message)
        );
    }

    #[view]
    public fun get_state_address(): address acquires CCIPReceiverState {
        let state = borrow_global<CCIPReceiverState>(@ccip_offramp);
        let state_signer = account::create_signer_with_capability(&state.signer_cap);
        signer::address_of(&state_signer)
    }

    struct CCIPReceiverProof has drop {}

    /// This function MUST remain private (not `public fun`). The `#[persistent]`
    /// attribute allows it to be stored as a closure without exposing it to external callers.
    /// Only the authorized offramp can invoke this via the closure registered with
    /// `receiver_registry::register_receiver_v2()`. Making this public would allow anyone to
    /// construct an `Any2AptosMessage` and execute arbitrary token transfers.
    #[persistent]
    fun ccip_receive_v2(message: client::Any2AptosMessage) acquires CCIPReceiverState {
        /* load state and rebuild a signer for the resource account */
        let state = borrow_global_mut<CCIPReceiverState>(@ccip_offramp);
        let state_signer = account::create_signer_with_capability(&state.signer_cap);

        let data = client::get_data(&message);

        let dest_token_amounts = client::get_dest_token_amounts(&message);

        if (dest_token_amounts.length() != 0 && data.length() != 0) {
            let final_recipient = from_bcs::to_address(data);

            for (i in 0..dest_token_amounts.length()) {
                let token_amount_ref = &dest_token_amounts[i];
                let token_addr = client::get_token(token_amount_ref);
                let amount = client::get_amount(token_amount_ref);

                // Implement the token transfer logic here

                let fa_token = object::address_to_object<Metadata>(token_addr);

                // Must use primary_fungible_store::transfer as token may be dispatchable
                primary_fungible_store::transfer(
                    &state_signer,
                    fa_token,
                    final_recipient,
                    amount
                );
            };

            event::emit(ForwardedTokens { final_recipient });
            event::emit_event(
                &mut state.forwarded_tokens_handle,
                ForwardedTokens { final_recipient }
            );
        } else if (data.length() != 0) {
            // Convert the vector<u8> to a string
            let message = string::utf8(data);

            event::emit(ReceivedMessage { message });
            event::emit_event(
                &mut state.received_message_handle, ReceivedMessage { message }
            );

        } else if (dest_token_amounts.length() != 0) {
            // Tokens only (no forwarding data) - keep them at receiver
            // Emit event to prove receiver was called
            let token_count = dest_token_amounts.length();
            event::emit(ReceivedTokensOnly { token_count });
            event::emit_event(
                &mut state.received_tokens_only_handle,
                ReceivedTokensOnly { token_count }
            );
        };

        // Simple abort condition for testing
        if (data == b"abort") {
            abort E_TEST_ABORT
        };
    }

    #[deprecated]
    /// Legacy V1 receive function, use ccip_receive_v2 as this supports dispatchable tokens
    /// Only switch to v2 once TokenPools are migrated to V2
    public fun ccip_receive<T: key>(_metadata: Object<T>): Option<u128> acquires CCIPReceiverState {
        /* load state and rebuild a signer for the resource account */
        let state = borrow_global_mut<CCIPReceiverState>(@ccip_offramp);
        let state_signer = account::create_signer_with_capability(&state.signer_cap);

        let message =
            receiver_registry::get_receiver_input(@ccip_offramp, CCIPReceiverProof {});

        let data = client::get_data(&message);

        let dest_token_amounts = client::get_dest_token_amounts(&message);

        if (dest_token_amounts.length() != 0 && data.length() != 0) {
            let final_recipient = from_bcs::to_address(data);

            for (i in 0..dest_token_amounts.length()) {
                let token_amount_ref = &dest_token_amounts[i];
                let token_addr = client::get_token(token_amount_ref);
                let amount = client::get_amount(token_amount_ref);

                // Implement the token transfer logic here

                let fa_token = object::address_to_object<Metadata>(token_addr);
                let fa_store_sender =
                    primary_fungible_store::ensure_primary_store_exists(
                        @ccip_offramp, fa_token
                    );
                let fa_store_receiver =
                    primary_fungible_store::ensure_primary_store_exists(
                        final_recipient, fa_token
                    );

                fungible_asset::transfer(
                    &state_signer,
                    fa_store_sender,
                    fa_store_receiver,
                    amount
                );
            };

            event::emit(ForwardedTokens { final_recipient });
            event::emit_event(
                &mut state.forwarded_tokens_handle,
                ForwardedTokens { final_recipient }
            );

        } else if (data.length() != 0) {

            // Convert the vector<u8> to a string
            let message = string::utf8(data);

            event::emit(ReceivedMessage { message });
            event::emit_event(
                &mut state.received_message_handle, ReceivedMessage { message }
            );

        } else if (dest_token_amounts.length() != 0) {
            // Tokens only (no forwarding data) - keep them at receiver
            // Emit event to prove receiver was called
            let token_count = dest_token_amounts.length();
            event::emit(ReceivedTokensOnly { token_count });
            event::emit_event(
                &mut state.received_tokens_only_handle,
                ReceivedTokensOnly { token_count }
            );
        };

        // Simple abort condition for testing
        if (data == b"abort") {
            abort E_TEST_ABORT
        };

        option::none()
    }

    public entry fun withdraw_token(
        sender: &signer, recipient: address, token_address: address
    ) acquires CCIPReceiverState {
        assert!(
            exists<CCIPReceiverState>(@ccip_offramp),
            E_RESOURCE_NOT_FOUND_ON_ACCOUNT
        );
        assert!(signer::address_of(sender) == @ccip_offramp, E_UNAUTHORIZED);

        let state = borrow_global_mut<CCIPReceiverState>(@ccip_offramp);
        let state_signer = account::create_signer_with_capability(&state.signer_cap);

        let fa_token = object::address_to_object<Metadata>(token_address);
        let balance = primary_fungible_store::balance(@ccip_offramp, fa_token);

        assert!(balance > 0, E_NO_TOKENS_AVAILABLE_TO_WITHDRAW);

        primary_fungible_store::transfer(&state_signer, fa_token, recipient, balance);
    }

    public fun test_init_module(publisher: &signer) {
        init_module(publisher);
    }

    /// Initialize without auto-registering (for testing V1/V2 manually)
    public fun test_init_state_only(publisher: &signer) {
        // Create a signer capability for the receiver account
        let signer_cap = account::create_test_signer_cap(signer::address_of(publisher));

        // Create a unique handle for each event type
        let received_message_handle =
            account::new_event_handle<ReceivedMessage>(publisher);
        let forwarded_tokens_handle =
            account::new_event_handle<ForwardedTokens>(publisher);
        let received_tokens_only_handle =
            account::new_event_handle<ReceivedTokensOnly>(publisher);

        // Move all state into the single resource struct
        move_to(
            publisher,
            CCIPReceiverState {
                signer_cap,
                received_message_handle,
                forwarded_tokens_handle,
                received_tokens_only_handle
            }
        );
    }

    public fun get_received_message_events(): vector<ReceivedMessage> acquires CCIPReceiverState {
        let state = borrow_global<CCIPReceiverState>(@ccip_offramp);
        event::emitted_events_by_handle<ReceivedMessage>(&state.received_message_handle)
    }

    public fun get_forwarded_tokens_events(): vector<ForwardedTokens> acquires CCIPReceiverState {
        let state = borrow_global<CCIPReceiverState>(@ccip_offramp);
        event::emitted_events_by_handle<ForwardedTokens>(&state.forwarded_tokens_handle)
    }

    public fun get_received_tokens_only_events(): vector<ReceivedTokensOnly> acquires CCIPReceiverState {
        let state = borrow_global<CCIPReceiverState>(@ccip_offramp);
        event::emitted_events_by_handle<ReceivedTokensOnly>(
            &state.received_tokens_only_handle
        )
    }

    public fun received_message_get_message(event: &ReceivedMessage): String {
        event.message
    }
}
