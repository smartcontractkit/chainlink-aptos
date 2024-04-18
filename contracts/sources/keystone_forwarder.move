module chainlink::keystone_forwarder {
	use aptos_framework::account::{Self};
	use aptos_framework::create_signer::create_signer;
	use std::error;
	use std::vector;
	use std::signer;

	const E_ACCOUNT_NOT_REGISTERED: u64 = 0;
	const E_INVALID_DATA_LENGTH: u64 = 1;

	struct Receiver has key {
		signer_cap: account::SignerCapability		
	}

	struct Mailbox has key, drop {
		report: vector<u8>
	}

    /// To generate resource account
    const RECEIVER_SEED: vector<u8> = b"receiver";

	public entry fun register(receiver: &signer) {
		let (resource_account, signer_cap) = account::create_resource_account(receiver, RECEIVER_SEED);
		let state = Receiver { signer_cap };
		move_to(receiver, state)
	}

    #[view]
    /// Returns `true` if `account_addr` is registered to receive Keystone report.
    public fun is_account_registered(account_addr: address): bool {
        exists<Mailbox>(account_addr)
    }

	public entry fun transmit(receiver: address, data: vector<u8>, signatures: vector<u8>) acquires Receiver {
		// TODO: check for resource account
        // if (!account::exists_at(receiver)) {
	       //  account::create_account(receiver);
        // };

		// TODO: check mailbox doesn't exist, if it does clear it first
        assert!(
            !is_account_registered(receiver),
            error::not_found(E_ACCOUNT_NOT_REGISTERED),
        );

		let mailbox = Mailbox { report: data }; // TODO: subset of data

		let state = borrow_global<Receiver>(receiver);
		let resource_signer = account::create_signer_with_capability(&state.signer_cap);
		move_to(&resource_signer, mailbox)
	}

	/// Called by the receiver module to fetch the report that was stored by the transmitter. This must be executed within a Move script together with transmit() so the operation is atomic!
	public fun consume_report(receiver: &signer): vector<u8> acquires Receiver, Mailbox {
		let state = borrow_global<Receiver>(signer::address_of(receiver));

		let resource_signer = account::create_signer_with_capability(&state.signer_cap);

		// TODO: have receiver be signer, then fetch resource_account for the signer
		move_from<Mailbox>(signer::address_of(&resource_signer)).report
	}
}
