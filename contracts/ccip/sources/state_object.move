/// The state_object module provides functionality for managing shared state objects.
module chainlink_ccip::state_object {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    
    // Constants
    const OBJECT_SEED: vector<u8> = b"CCIP_STATE_OBJECT";
    
    struct StateObject has key {
        id: UID
    }
    
    struct StateObjectCap has key, store {
        id: UID
    }
    
    fun init(ctx: &mut TxContext) {
        // Create the state object
        let state_object = StateObject {
            id: object::new(ctx)
        };
        
        // Create the capability object
        let state_object_cap = StateObjectCap {
            id: object::new(ctx)
        };
        
        // Share the state object
        transfer::share_object(state_object);
        
        // Transfer the capability to the sender
        transfer::transfer(state_object_cap, tx_context::sender(ctx));
    }
    
    public fun object_address(): address {
        @chainlink_ccip
    }
    
    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx);
    }
}
