module mcms::merkle {
    use std::aptos_hash::keccak256;
    use std::bcs;
    use std::string::String;
    use aptos_std::secp256k1;

    use mcms::params;

    const E_INVALID_ROOT_LEN: u64 = 0;
    const E_INVALID_SIGNATURE_LEN: u64 = 1;
    const E_INVALID_V_SIGNATURE: u64 = 2;
    const E_FAILED_ECDSA_RECOVER: u64 = 3;
    const E_INVALID_PARAMETERS: u64 = 4;
    const E_MODULE_NAME_TOO_LONG: u64 = 5;
    const E_FUNCTION_NAME_TOO_LONG: u64 = 6;

    struct Op has copy, drop {
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function: String,
        data: vector<u8>
    }

    public fun verify_merkle_proof(
        proof: vector<vector<u8>>,
        root: vector<u8>,
        leaf: vector<u8>
    ): bool {
        let computed_hash = leaf;
        proof.for_each_ref(
            |proof_element| {
                let (left, right) =
                    if (params::vector_u8_gt(&computed_hash, proof_element)) {
                        (*proof_element, computed_hash)
                    } else {
                        (computed_hash, *proof_element)
                    };
                let hash_input: vector<u8> = left;
                hash_input.append(right);
                computed_hash = keccak256(hash_input);
            }
        );
        computed_hash == root
    }

    public fun compute_eth_message_hash(
        root: vector<u8>, valid_until: u64
    ): vector<u8> {
        // abi.encode(root (bytes32), valid_until)
        let valid_until_bytes = params::encode_uint(valid_until, 32);
        assert!(root.length() == 32, E_INVALID_ROOT_LEN); // root should be 32 bytes
        let abi_encoded_params = &mut root;
        abi_encoded_params.append(valid_until_bytes);

        // keccak256(abi_encoded_params)
        let hashed_encoded_params = keccak256(*abi_encoded_params);

        // ECDSA.toEthSignedMessageHash()
        let eth_msg_prefix = b"\x19Ethereum Signed Message:\n32";
        let hash = &mut eth_msg_prefix;
        hash.append(hashed_encoded_params);
        keccak256(*hash)
    }

    public fun ecdsa_recover_evm_addr(
        eth_signed_message_hash: vector<u8>, signature: vector<u8>
    ): vector<u8> {
        // ensure signature has correct length - (r,s,v) concatenated = 65 bytes
        assert!(signature.length() == 65, E_INVALID_SIGNATURE_LEN);
        // extract v from signature
        let v = signature.pop_back();
        // convert 64 byte signature into ECDSASignature struct
        let sig = secp256k1::ecdsa_signature_from_bytes(signature);
        // Aptos uses the rust libsecp256k1 parse() under the hood which has a different numbering scheme
        // see: https://docs.rs/libsecp256k1/latest/libsecp256k1/struct.RecoveryId.html#method.parse_rpc
        assert!(v >= 27 && v < 27 + 4, E_INVALID_V_SIGNATURE);
        let v = v - 27;

        // retrieve signer public key
        let public_key =
            aptos_std::secp256k1::ecdsa_recover(eth_signed_message_hash, v, &sig);
        assert!(public_key.is_some(), E_FAILED_ECDSA_RECOVER);

        // return last 20 bytes of hashed public key as the recovered ethereum address
        let public_key_bytes =
            secp256k1::ecdsa_raw_public_key_to_bytes(&public_key.extract());
        (&mut keccak256(public_key_bytes)).trim(12) // trims publicKeyBytes to 12 bytes, returns trimmed last 20 bytes
    }

    // computes keccak256(abi.encode(domain_separator, op))
    public fun hash_op_leaf(domain_separator: vector<u8>, op: Op): vector<u8> {
        let role = params::encode_uint(op.role, 32);
        let chain_id = params::encode_uint(op.chain_id, 32);
        let multisig = bcs::to_bytes(&op.multisig);
        let nonce = params::encode_uint(op.nonce, 32);
        let to = bcs::to_bytes(&op.to);

        assert!(op.module_name.length() <= 64, E_MODULE_NAME_TOO_LONG);
        let module_name = *op.module_name.bytes();
        params::left_pad_vec(&mut module_name, 64);

        assert!(op.function.length() <= 64, E_FUNCTION_NAME_TOO_LONG);
        let function = *op.function.bytes();
        params::left_pad_vec(&mut function, 64);

        let hash_preimage: vector<u8> = vector[];
        hash_preimage.append(domain_separator);
        hash_preimage.append(role);
        hash_preimage.append(chain_id);
        hash_preimage.append(multisig);
        hash_preimage.append(nonce);
        hash_preimage.append(to);
        hash_preimage.append(module_name);
        hash_preimage.append(function);
        hash_preimage.append(op.data);

        // right pad op.data to multiple of 32 bytes
        let pad_amount = 32 - (op.data.length() % 32);
        params::right_pad_vec(&mut hash_preimage, pad_amount);
        while (pad_amount > 0) {
            hash_preimage.push_back(0);
            pad_amount -= 1;
        };

        // since we are using this in a merkle tree/proof, hash_preimage should be greater than 64 bytes
        // to prevent collisions with internal nodes. the above operations already guarantee this so no need to check.
        keccak256(hash_preimage)
    }

    public fun role(op: Op): u8 {
        op.role
    }

    public fun chain_id(op: Op): u256 {
        op.chain_id
    }

    public fun multisig(op: Op): address {
        op.multisig
    }

    public fun nonce(op: Op): u64 {
        op.nonce
    }

    public fun to(op: Op): address {
        op.to
    }

    public fun module_name(op: Op): String {
        op.module_name
    }

    public fun function(op: Op): String {
        op.function
    }

    public fun data(op: Op): vector<u8> {
        op.data
    }

    public fun create_op(
        role: u8,
        chain_id: u256,
        multisig: address,
        nonce: u64,
        to: address,
        module_name: String,
        function: String,
        data: vector<u8>
    ): Op {
        Op { role, chain_id, multisig, nonce, to, module_name, function, data }
    }
}
