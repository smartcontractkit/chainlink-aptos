module usdc_token_pool::usdc_token_pool;

use std::string::{Self, String};

use ccip::eth_abi;
use ccip::token_admin_registry;
use ccip_token_pool::token_pool;

/// A domain is a USDC representation of a destination chain.
/// @dev Zero is a valid domain identifier.
/// @dev The address to mint on the destination chain is the corresponding USDC pool.
/// @dev The allowedCaller represents the contract authorized to call receiveMessage on the destination CCTP message transmitter.
/// For EVM dest pool version 1.6.1, this is the MessageTransmitterProxy of the destination chain.
/// For EVM dest pool version 1.5.1, this is the destination chain's token pool.
public struct Domain has store, drop, copy {
    allowed_caller: vector<u8>, //  Address allowed to mint on the domain
    domain_identifier: u32, // Unique domain ID
    enabled: bool,
}

public struct DomainsSet has copy, drop {
    allowed_caller: vector<u8>,
    domain_identifier: u32,
    remote_chain_selector: u64,
    enabled: bool,
}

// ================================================================
// |                             Init                             |
// ================================================================

public fun type_and_version(): String {
    string::utf8(b"USDCTokenPool 1.6.0")
}
