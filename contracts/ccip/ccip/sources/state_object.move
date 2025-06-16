/// This module creates a single object for storing CCIP state resources in order to:
///
/// - simplify ownership management
/// - simplify observability: all resources and events can be queried and viewed at a single address
/// - decouple module deployment and initialization: the CCIP module will be deployed using the
///   recommended object code deployment approach, but initialization requires various
///   "constructor" parameters that cannot be passed it at deploy (ie. init_module()) time.
///   Object code deployment only allows for publishing and upgrading modules, with no way to
///   retrieve a signer to store resources (see: 0x1::object_code_deployment), so a different
///   object is necessary.
module ccip::state_object {
    use std::account;
    use std::error;
    use std::object::{Self, ExtendRef, TransferRef};
    use std::signer;

    friend ccip::auth;
    friend ccip::fee_quoter;
    friend ccip::nonce_manager;
    friend ccip::receiver_registry;
    friend ccip::rmn_remote;
    friend ccip::token_admin_registry;

    struct StateObjectRefs has key {
        extend_ref: ExtendRef,
        transfer_ref: TransferRef
    }

    const E_NOT_OBJECT_DEPLOYMENT: u64 = 1;

    fun init_module(publisher: &signer) {
        assert!(
            object::is_object(signer::address_of(publisher)),
            error::invalid_state(E_NOT_OBJECT_DEPLOYMENT)
        );

        init_module_internal(publisher);
    }

    inline fun init_module_internal(publisher: &signer) {
        let constructor_ref = object::create_named_object(publisher, b"CCIPStateObject");

        let extend_ref = object::generate_extend_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let object_signer = object::generate_signer(&constructor_ref);

        // create an Account on the object for event handles.
        account::create_account_if_does_not_exist(
            object::address_from_constructor_ref(&constructor_ref)
        );

        move_to(&object_signer, StateObjectRefs { extend_ref, transfer_ref });
    }

    #[view]
    public fun get_object_address(): address {
        object_address()
    }

    public(friend) inline fun object_address(): address {
        // hard code the object seed directly in order to keep the function inline.
        object::create_object_address(&@ccip, b"CCIPStateObject")
    }

    public(friend) fun object_signer(): signer acquires StateObjectRefs {
        let store = borrow_global<StateObjectRefs>(object_address());
        object::generate_signer_for_extending(&store.extend_ref)
    }

    #[test_only]
    public fun init_module_for_testing(publisher: &signer) {
        init_module_internal(publisher);
    }
}
