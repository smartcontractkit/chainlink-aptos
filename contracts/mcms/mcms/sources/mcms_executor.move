/// This module helps to stage large mcms::execute invocations, that cannot be done in a single
/// transaction due to the transaction size limit.
module mcms::mcms_executor {
    use std::signer;
    use std::string::String;

    use mcms::mcms;

    struct PendingExecute has key, store {
        data: vector<u8>,
        proofs: vector<vector<u8>>
    }

    public entry fun stage_data(
        caller: &signer, data_chunk: vector<u8>, partial_proofs: vector<vector<u8>>
    ) acquires PendingExecute {
        let caller_address = signer::address_of(caller);
        if (!exists<PendingExecute>(caller_address)) {
            move_to(
                caller,
                PendingExecute { data: vector[], proofs: vector[] }
            );
        };
        let pending_execute = borrow_global_mut<PendingExecute>(caller_address);
        if (!data_chunk.is_empty()) {
            pending_execute.data.append(data_chunk);
        };
        if (!partial_proofs.is_empty()) {
            pending_execute.proofs.append(partial_proofs);
        };
    }

    public entry fun stage_data_and_execute(
        caller: &signer,
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function: String,
        data_chunk: vector<u8>,
        partial_proofs: vector<vector<u8>>
    ) acquires PendingExecute {
        if (!exists<PendingExecute>(signer::address_of(caller))) {
            move_to(
                caller,
                PendingExecute { data: vector[], proofs: vector[] }
            );
        };
        let PendingExecute { data, proofs } =
            move_from<PendingExecute>(signer::address_of(caller));
        if (!data_chunk.is_empty()) {
            data.append(data_chunk);
        };
        if (!partial_proofs.is_empty()) {
            proofs.append(partial_proofs);
        };
        mcms::execute(
            role,
            chain_id,
            multisig,
            nonce,
            to,
            module_name,
            function,
            data,
            proofs
        );
    }

    public entry fun clear_staged_data(caller: &signer) acquires PendingExecute {
        let PendingExecute { data: _, proofs: _ } =
            move_from<PendingExecute>(signer::address_of(caller));
    }
}
