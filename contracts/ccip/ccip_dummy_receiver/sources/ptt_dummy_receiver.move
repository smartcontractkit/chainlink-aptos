module ccip_dummy_receiver::ptt_dummy_receiver {
    use std::account;
    use std::event;
    use std::object::{Self};
    use std::string::{Self, String};
    use std::fungible_asset::{Metadata};
    use std::resource_account;
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

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"PTTDummyReceiver 1.6.0")
    }

    const MODULE_NAME: vector<u8> = b"ptt_dummy_receiver";

    fun init_module(publisher: &signer) {
        let signer_cap =
            resource_account::retrieve_resource_account_cap(publisher, @deployer);

        let received_message_handle =
            account::new_event_handle<ReceivedMessage>(publisher);
        let forwarded_tokens_handle =
            account::new_event_handle<ForwardedTokens>(publisher);
        let received_tokens_only_handle =
            account::new_event_handle<ReceivedTokensOnly>(publisher);

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
            publisher,
            MODULE_NAME,
            |message| ccip_receive_v2(message),
            CCIPReceiverProof {}
        );
    }

    #[view]
    public fun get_state_address(): address acquires CCIPReceiverState {
        let state = borrow_global<CCIPReceiverState>(@ccip_dummy_receiver);
        let state_signer = account::create_signer_with_capability(&state.signer_cap);
        signer::address_of(&state_signer)
    }

    struct CCIPReceiverProof has drop {}

    public fun ccip_receive_v2(message: client::Any2AptosMessage) acquires CCIPReceiverState {
        /* load state and rebuild a signer for the resource account */
        let state = borrow_global_mut<CCIPReceiverState>(@ccip_dummy_receiver);
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
                &mut state.forwarded_tokens_handle, ForwardedTokens { final_recipient }
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
            abort 1
        };
    }

    public entry fun withdraw_token(
        sender: &signer, recipient: address, token_address: address
    ) acquires CCIPReceiverState {
        assert!(
            exists<CCIPReceiverState>(@ccip_dummy_receiver),
            E_RESOURCE_NOT_FOUND_ON_ACCOUNT
        );
        assert!(signer::address_of(sender) == @ccip_dummy_receiver, E_UNAUTHORIZED);

        let state = borrow_global_mut<CCIPReceiverState>(@ccip_dummy_receiver);
        let state_signer = account::create_signer_with_capability(&state.signer_cap);

        let fa_token = object::address_to_object<Metadata>(token_address);
        let balance = primary_fungible_store::balance(@ccip_dummy_receiver, fa_token);

        assert!(balance > 0, E_NO_TOKENS_AVAILABLE_TO_WITHDRAW);

        primary_fungible_store::transfer(&state_signer, fa_token, recipient, balance);
    }
}
