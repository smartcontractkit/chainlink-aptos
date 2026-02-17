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
        data: vector<u8>
    }

    struct CCIPReceiverState has key {
        signer_cap: account::SignerCapability,
        received_message_events: event::EventHandle<ReceivedMessage>
    }

    const E_RESOURCE_NOT_FOUND_ON_ACCOUNT: u64 = 1;
    const E_UNAUTHORIZED: u64 = 2;
    const E_NO_TOKENS_AVAILABLE_TO_WITHDRAW: u64 = 3;
    const E_TEST_ABORT: u64 = 4;

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"PTTDummyReceiver 1.6.0")
    }

    fun init_module(publisher: &signer) {
        let signer_cap =
            resource_account::retrieve_resource_account_cap(publisher, @deployer);

        let received_message_events =
            account::new_event_handle<ReceivedMessage>(publisher);

        move_to(publisher, CCIPReceiverState { signer_cap, received_message_events });

        // Default to V2 registration
        receiver_registry::register_receiver_v2(
            publisher, |message| ccip_receive_v2(message)
        );
    }

    #[view]
    public fun get_state_address(): address acquires CCIPReceiverState {
        let state = borrow_global<CCIPReceiverState>(@ccip_dummy_receiver);
        let state_signer = account::create_signer_with_capability(&state.signer_cap);
        signer::address_of(&state_signer)
    }

    #[persistent]
    /// This function MUST remain private (not `public fun`). The `#[persistent]`
    /// attribute allows it to be stored as a closure without exposing it to external callers.
    /// Only the authorized offramp can invoke this via the closure registered with
    /// `receiver_registry::register_receiver_v2()`. Making this public would allow anyone to
    /// construct an `Any2AptosMessage` and execute arbitrary token transfers.
    fun ccip_receive_v2(message: client::Any2AptosMessage) acquires CCIPReceiverState {
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
        };

        event::emit(ReceivedMessage { data });
        event::emit_event(&mut state.received_message_events, ReceivedMessage { data });

        // Simple abort condition for testing
        if (data == b"abort") {
            abort E_TEST_ABORT
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
