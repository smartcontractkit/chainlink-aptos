module chainlink::data_feeds_router {
    use std::account;
    use std::resource_account;
    use std::simple_map::{Self, SimpleMap};
    use std::vector;

    use chainlink::data_feeds_registry;

    struct DataFeedsRouter has key, store, drop {
        owner_address: address,
        signer_cap: account::SignerCapability,

        feed_id_to_registry_address: SimpleMap<vector<u8>, address>,

        // TODO: fee manager
    }

    struct NonbillableAccessCapability has drop, store {}

    #[event]
    struct NonbillableUserAdded has drop, store {
        user: address
    }

    #[event]
    struct NonbillableUserRemoved has drop, store {
        user: address
    }

    const UNAUTHORIZED_NONBILLABLE_ACCESS: u64 = 0;

    public entry fun initialize(resource_account: &signer, owner_address: address) {
        // TODO: this assumes that the passed in owner address owns the resource account.
        let signer_cap = resource_account::retrieve_resource_account_cap(resource_account, owner_address);

        move_to(resource_account, DataFeedsRouter {
            owner_address: owner_address,
            signer_cap: signer_cap,

            feed_id_to_registry_address: simple_map::new(),
        });
    }
}
