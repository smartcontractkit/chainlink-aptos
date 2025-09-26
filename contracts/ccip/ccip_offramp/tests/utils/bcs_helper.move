#[test_only]
module ccip_offramp::bcs_helper {
    use std::bcs;
    use ccip_offramp::offramp::{Any2AptosTokenTransfer};

    public fun create_execution_report_bytes(
        source_chain_selector: u64,
        message_id: vector<u8>,
        dest_chain_selector: u64,
        sequence_number: u64,
        nonce: u64,
        sender: vector<u8>,
        data: vector<u8>,
        receiver: address,
        gas_limit: u256,
        token_transfers: vector<Any2AptosTokenTransfer>,
        offchain_token_data: vector<vector<u8>>,
        proofs: vector<vector<u8>>
    ): vector<u8> {
        // Serialize the execution report sequentially to match deserializer
        let report_bytes = vector[];

        // First serialize source_chain_selector
        report_bytes.append(bcs::to_bytes(&source_chain_selector));

        // Then serialize message parts in the exact order they're deserialized
        report_bytes.append(message_id); // Raw bytes for fixed-length vector deserialization
        report_bytes.append(bcs::to_bytes(&source_chain_selector)); // header.source_chain_selector
        report_bytes.append(bcs::to_bytes(&dest_chain_selector));
        report_bytes.append(bcs::to_bytes(&sequence_number));
        report_bytes.append(bcs::to_bytes(&nonce));

        // Then message fields after header
        report_bytes.append(bcs::to_bytes(&sender));
        report_bytes.append(bcs::to_bytes(&data));
        report_bytes.append(bcs::to_bytes(&receiver));
        report_bytes.append(bcs::to_bytes(&gas_limit));

        // Serialize token transfers
        report_bytes.append(bcs::to_bytes(&token_transfers));

        // Serialize offchain token data and proofs
        report_bytes.append(bcs::to_bytes(&offchain_token_data));

        // Manually serialize proofs vector: length + raw 32-byte elements
        // This is done as the proofs are deserialized as a fixed-length vector of 32 bytes.
        let proofs_len = proofs.length() as u8;
        report_bytes.push_back(proofs_len); // uleb128 encoding for small numbers
        proofs.for_each_ref(
            |proof| {
                report_bytes.append(*proof); // Raw 32-byte proof data
            }
        );

        report_bytes
    }
}
