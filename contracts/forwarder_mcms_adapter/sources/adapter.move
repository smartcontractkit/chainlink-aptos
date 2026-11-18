/// MCMS adapter for the CRE forwarders (`platform::forwarder` and `platform_secondary::forwarder`).
///
/// The forwarders predate MCMS and cannot be redeployed (receivers are compiled against their
/// addresses), so they have no MCMS entrypoint of their own. This package bridges the two:
///
/// ```
/// mcms::execute -> timelock_dispatch -> mcms_registry (dispatchable FA hook)
///   -> adapter::mcms_entrypoint -> mcms_registry::get_callback_params
///   -> <forwarder>::<fn>(&adapter_owner_signer, ...)          (static call)
/// ```
///
/// MCMS needs no compile-time dependency on this package; it reaches `mcms_entrypoint` through the
/// dispatch hook registered in `init_module`. The signer handed to us by `get_callback_params` is
/// the MCMS owner resource account registered for this package (`mcms_owner_address()`). Setting
/// both forwarders' owner to that account (via their two-step `transfer_ownership` /
/// `accept_ownership`) gives MCMS, and only MCMS, owner control of both forwarders.
///
/// Calls: every function takes the target forwarder address as its first BCS argument, which must
/// be `@platform` or `@platform_secondary`. The remaining arguments and the function names match
/// the forwarder's owner-gated entry functions exactly:
///
/// | function             | args after `forwarder: address`                                         |
/// |----------------------|-------------------------------------------------------------------------|
/// | `set_config`         | `don_id: u32, config_version: u32, f: u8, oracles: vector<vector<u8>>`  |
/// | `clear_config`       | `don_id: u32, config_version: u32`                                      |
/// | `transfer_ownership` | `to: address`                                                           |
/// | `accept_ownership`   | (none)                                                                  |
///
/// Not covered, because they are not owner-gated: `forwarder::report` (anyone may transmit a
/// signed report), `storage::register` (called by receivers), `storage::migrate_to_v2`
/// (permissionless) and views.
///
/// The adapter holds no state and has no admin functions; its only authority is what MCMS
/// exercises through `mcms_entrypoint`.
module forwarder_mcms_adapter::adapter {
    use std::code::PackageRegistry;
    use std::error;
    use std::object::{Self, Object};
    use std::option::{Self, Option};
    use std::string::{Self, String};

    use mcms::bcs_stream::{Self, BCSStream};
    use mcms::mcms_registry;

    use platform::forwarder as primary;
    use platform_secondary::forwarder as secondary;

    /// The function name passed by MCMS is not one this adapter supports.
    const E_UNKNOWN_FUNCTION: u64 = 1;
    /// The target forwarder address is neither `@platform` nor `@platform_secondary`.
    const E_UNKNOWN_FORWARDER: u64 = 2;
    /// `@platform` and `@platform_secondary` must be distinct.
    const E_SAME_FORWARDER_ADDRESSES: u64 = 3;
    /// The adapter must be published by MCMS (mcms_deployer), so that only MCMS can upgrade it.
    const E_NOT_PUBLISHED_BY_MCMS: u64 = 4;

    /// Module name registered with mcms_registry. MCMS proposals target
    /// `<adapter address>::adapter::<function>`.
    const MODULE_NAME: vector<u8> = b"adapter";

    struct McmsCallback has drop {}

    fun init_module(publisher: &signer) {
        // Security: whoever can upgrade this package can make mcms_entrypoint do anything with
        // the forwarder-owner signer during any MCMS op. Refuse to exist unless the package's code
        // object is owned by MCMS (i.e. it was published through mcms_deployer), so upgrade
        // authority is MCMS-only from the first block. An EOA-published copy aborts here, either
        // on this assert or inside is_owned_code_object (address not registered with MCMS).
        assert!(
            object::object_exists<PackageRegistry>(@forwarder_mcms_adapter)
                && mcms_registry::is_owned_code_object(@forwarder_mcms_adapter),
            error::permission_denied(E_NOT_PUBLISHED_BY_MCMS)
        );
        register(publisher);
    }

    fun register(publisher: &signer) {
        // Routing below relies on the two addresses being different.
        assert!(
            @platform != @platform_secondary,
            error::invalid_argument(E_SAME_FORWARDER_ADDRESSES)
        );
        mcms_registry::register_entrypoint(
            publisher, string::utf8(MODULE_NAME), McmsCallback {}
        );
    }

    #[view]
    public fun type_and_version(): String {
        string::utf8(b"ForwarderMcmsAdapter 1.0.0")
    }

    #[view]
    /// The account MCMS signs as when calling through this adapter. Both forwarders' owner must be
    /// set to this address for MCMS to control them.
    public fun mcms_owner_address(): address {
        mcms_registry::get_registered_owner_address(@forwarder_mcms_adapter)
    }

    #[view]
    /// The forwarders this adapter can target: (primary, secondary).
    public fun forwarders(): (address, address) {
        (@platform, @platform_secondary)
    }

    /// MCMS dispatch callback. Only callable meaningfully during an MCMS-executed operation:
    /// `get_callback_params` aborts unless mcms_registry is currently dispatching to this package.
    public fun mcms_entrypoint<T: key>(_metadata: Object<T>): Option<u128> {
        let (caller, function, data) =
            mcms_registry::get_callback_params(@forwarder_mcms_adapter, McmsCallback {});

        let function_bytes = *function.bytes();
        let stream = bcs_stream::new(data);

        if (function_bytes == b"set_config") {
            let is_primary = deserialize_target(&mut stream);
            let don_id = bcs_stream::deserialize_u32(&mut stream);
            let config_version = bcs_stream::deserialize_u32(&mut stream);
            let f = bcs_stream::deserialize_u8(&mut stream);
            let oracles =
                bcs_stream::deserialize_vector(
                    &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
                );
            bcs_stream::assert_is_consumed(&stream);
            if (is_primary) {
                primary::set_config(&caller, don_id, config_version, f, oracles)
            } else {
                secondary::set_config(&caller, don_id, config_version, f, oracles)
            }
        } else if (function_bytes == b"clear_config") {
            let is_primary = deserialize_target(&mut stream);
            let don_id = bcs_stream::deserialize_u32(&mut stream);
            let config_version = bcs_stream::deserialize_u32(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            if (is_primary) {
                primary::clear_config(&caller, don_id, config_version)
            } else {
                secondary::clear_config(&caller, don_id, config_version)
            }
        } else if (function_bytes == b"transfer_ownership") {
            let is_primary = deserialize_target(&mut stream);
            let to = bcs_stream::deserialize_address(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            if (is_primary) {
                primary::transfer_ownership(&caller, to)
            } else {
                secondary::transfer_ownership(&caller, to)
            }
        } else if (function_bytes == b"accept_ownership") {
            let is_primary = deserialize_target(&mut stream);
            bcs_stream::assert_is_consumed(&stream);
            if (is_primary) {
                primary::accept_ownership(&caller)
            } else {
                secondary::accept_ownership(&caller)
            }
        } else {
            abort error::invalid_argument(E_UNKNOWN_FUNCTION)
        };

        option::none()
    }

    /// Reads the target forwarder address: true for `@platform`, false for `@platform_secondary`,
    /// aborts with E_UNKNOWN_FORWARDER otherwise.
    fun deserialize_target(stream: &mut BCSStream): bool {
        let target = bcs_stream::deserialize_address(stream);
        if (target == @platform) { true }
        else if (target == @platform_secondary) { false }
        else {
            abort error::invalid_argument(E_UNKNOWN_FORWARDER)
        }
    }

    // ========================== TEST ONLY ==========================

    #[test_only]
    /// Registers the entrypoint WITHOUT the published-by-MCMS check: unit tests cannot publish a
    /// real code object through mcms_deployer. The check itself is exercised by
    /// `test_init_module_strict` (must abort) and on testnet (forwarder_mcms_poc).
    public fun test_init_module(publisher: &signer) {
        register(publisher);
    }

    #[test_only]
    /// The real init_module, including the published-by-MCMS check.
    public fun test_init_module_strict(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun module_name(): String {
        string::utf8(MODULE_NAME)
    }
}
