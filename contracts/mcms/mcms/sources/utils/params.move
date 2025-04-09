module mcms::params {
    use std::string::String;
    use std::bcs;
    use mcms::bcs_stream;
    use std::aptos_hash::keccak256;

    const E_CMP_VECTORS_DIFF_LEN: u64 = 0;
    const E_INVALID_PARAMETERS: u64 = 1;

    struct Call has copy, drop, store {
        function: Function,
        data: vector<u8>
    }

    struct Function has copy, drop, store {
        target: address,
        module_name: String,
        function_name: String
    }

    public fun hash_operation_batch(
        calls: vector<Call>, predecessor: vector<u8>, salt: vector<u8>
    ): vector<u8> {
        // This function replicates Ethereum's keccak256(abi.encode(calls, predecessor, salt))
        // In Solidity, this is simply packing the parameters together and hashing them

        // Create a single packed vector for all data
        let packed = vector[];

        // Encode the calls array
        // First encode the length of the calls array
        packed.append(bcs::to_bytes(&calls.length()));

        // Then encode each call
        for (i in 0..calls.length()) {
            let call = calls.borrow(i);
            packed.append(bcs::to_bytes(call));
        };

        packed.append(predecessor);
        packed.append(salt);

        keccak256(packed)
    }

    public fun create_calls(
        targets: vector<address>,
        module_names: vector<String>,
        function_names: vector<String>,
        datas: vector<vector<u8>>
    ): vector<Call> {
        let len = targets.length();
        assert!(
            len == module_names.length()
                && len == function_names.length()
                && len == datas.length(),
            E_INVALID_PARAMETERS
        );

        let calls = vector[];
        for (i in 0..len) {
            let target = targets[i];
            let module_name = module_names[i];
            let function_name = function_names[i];
            let data = datas[i];
            let function = create_function(target, module_name, function_name);
            let call = create_call(function, data);
            calls.push_back(call);
        };

        calls
    }

    public fun create_function(
        target: address, module_name: String, function_name: String
    ): Function {
        Function { target, module_name, function_name }
    }

    public fun create_call(function: Function, data: vector<u8>): Call {
        Call { function, data }
    }

    public fun call_function(call: Call): Function {
        call.function
    }

    public fun data(call: Call): vector<u8> {
        call.data
    }

    public fun target(function: Function): address {
        function.target
    }

    public fun module_name(function: Function): String {
        function.module_name
    }

    public fun function_name(function: Function): String {
        function.function_name
    }

    public fun deserialize_update_min_delay_params(data: vector<u8>): u64 {
        let stream = bcs_stream::new(data);
        let min_delay = bcs_stream::deserialize_u64(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        min_delay
    }

    public fun deserialize_schedule_batch_params(
        data: vector<u8>
    ): (
        vector<address>,
        vector<String>,
        vector<String>,
        vector<vector<u8>>,
        vector<u8>,
        vector<u8>,
        u64
    ) {
        let stream = bcs_stream::new(data);
        let targets =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_address(stream)
            );
        let module_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        let function_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        let datas =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );
        let predecessor = bcs_stream::deserialize_vector_u8(&mut stream);
        let salt = bcs_stream::deserialize_vector_u8(&mut stream);
        let delay = bcs_stream::deserialize_u64(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        (targets, module_names, function_names, datas, predecessor, salt, delay)
    }

    public fun deserialize_bypasser_execute_batch_params(
        data: vector<u8>
    ): (vector<address>, vector<String>, vector<String>, vector<vector<u8>>) {
        let stream = bcs_stream::new(data);
        let targets =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_address(stream)
            );
        let module_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        let function_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        let datas =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );
        bcs_stream::assert_is_consumed(&stream);
        (targets, module_names, function_names, datas)
    }

    public fun deserialize_block_function_params(data: vector<u8>): (address, String, String) {
        let stream = bcs_stream::new(data);
        let target = bcs_stream::deserialize_address(&mut stream);
        let module_name = bcs_stream::deserialize_string(&mut stream);
        let function_name = bcs_stream::deserialize_string(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        (target, module_name, function_name)
    }

    public fun deserialize_unblock_function_params(data: vector<u8>):
        (address, String, String) {
        deserialize_block_function_params(data)
    }

    public fun deserialize_initialize_roles_params(
        data: vector<u8>
    ): (vector<address>, vector<address>, vector<address>, address) {
        let stream = bcs_stream::new(data);
        let proposer_members =
            bcs_stream::deserialize_vector(
                &mut stream, |s| bcs_stream::deserialize_address(s)
            );
        let canceller_members =
            bcs_stream::deserialize_vector(
                &mut stream, |s| bcs_stream::deserialize_address(s)
            );
        let bypasser_members =
            bcs_stream::deserialize_vector(
                &mut stream, |s| bcs_stream::deserialize_address(s)
            );
        let sender_address = bcs_stream::deserialize_address(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        (proposer_members, canceller_members, bypasser_members, sender_address)
    }

    public fun deserialize_grant_role_params(data: vector<u8>): (u8, address) {
        let stream = bcs_stream::new(data);
        let role = bcs_stream::deserialize_u8(&mut stream);
        let account = bcs_stream::deserialize_address(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        (role, account)
    }

    public fun deserialize_execute_batch_params(
        data: vector<u8>
    ): (
        vector<address>,
        vector<String>,
        vector<String>,
        vector<vector<u8>>,
        vector<u8>,
        vector<u8>
    ) {
        let stream = bcs_stream::new(data);
        let targets =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_address(stream)
            );
        let module_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        let function_names =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_string(stream)
            );
        let datas =
            bcs_stream::deserialize_vector(
                &mut stream, |stream| bcs_stream::deserialize_vector_u8(stream)
            );
        let predecessor = bcs_stream::deserialize_vector_u8(&mut stream);
        let salt = bcs_stream::deserialize_vector_u8(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        (targets, module_names, function_names, datas, predecessor, salt)
    }

    public fun deserialize_revoke_role_params(data: vector<u8>): (u8, address) {
        deserialize_grant_role_params(data)
    }

    public fun deserialize_initialize_params(data: vector<u8>): u64 {
        let stream = bcs_stream::new(data);
        let min_delay = bcs_stream::deserialize_u64(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        min_delay
    }

    public fun deserialize_cancel_params(data: vector<u8>): vector<u8> {
        let stream = bcs_stream::new(data);
        let id = bcs_stream::deserialize_vector_u8(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        id
    }

    public fun deserialize_update_delay_params(data: vector<u8>): u64 {
        let stream = bcs_stream::new(data);
        let new_delay = bcs_stream::deserialize_u64(&mut stream);
        bcs_stream::assert_is_consumed(&stream);
        new_delay
    }

    public fun encode_uint<T: drop>(input: T, num_bytes: u64): vector<u8> {
        let bcs_bytes = bcs::to_bytes(&input);

        let len = bcs_bytes.length();
        if (len < num_bytes) {
            let bytes_to_pad = num_bytes - len;
            for (i in 0..bytes_to_pad) {
                bcs_bytes.push_back(0);
            };
        };

        // little endian to big endian
        bcs_bytes.reverse();

        bcs_bytes
    }

    public fun right_pad_vec(v: &mut vector<u8>, num_bytes: u64) {
        let len = v.length();
        if (len < num_bytes) {
            let bytes_to_pad = num_bytes - len;
            for (i in 0..bytes_to_pad) {
                v.push_back(0);
            };
        };
    }

    public fun left_pad_vec(v: &mut vector<u8>, num_bytes: u64) {
        let len = v.length();
        if (len < num_bytes) {
            let bytes_to_pad = num_bytes - len;
            v.reverse();
            for (i in 0..bytes_to_pad) {
                v.push_back(0);
            };
            v.reverse();
        };
    }

    /// compares two vectors of equal length, returns true if a > b, false otherwise.
    public fun vector_u8_gt(a: &vector<u8>, b: &vector<u8>): bool {
        let len = a.length();
        assert!(len == b.length(), E_CMP_VECTORS_DIFF_LEN);

        if (len == 0) {
            return false
        };

        // compare each byte until not equal
        for (i in 0..len) {
            let byte_a = a[i];
            let byte_b = b[i];
            if (byte_a > byte_b) {
                return true
            } else if (byte_a < byte_b) {
                return false
            };
        };

        // vectors are equal, a == b
        false
    }

    public fun vector_starts_with(v: &vector<u8>, prefix: &vector<u8>): bool {
        let prefix_len = prefix.length();

        if (prefix_len > v.length()) {
            return false
        };

        for (i in 0..prefix_len) {
            if (v[i] != prefix[i]) {
                return false
            };
        };

        true
    }
}
