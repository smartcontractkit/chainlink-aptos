#[test_only]
module mcms::object_code_util {
    use std::object_code_deployment;
    use std::account;
    use std::bcs;
    use std::vector;
    use std::object;
    use std::signer;
    const OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR: vector<u8> = b"aptos_framework::object_code_deployment";

    public fun publish_code_object(
        deployer: &signer, metadata: vector<u8>, code: vector<vector<u8>>
    ): address {
        let deployer_address = signer::address_of(deployer);
        let object_seed = object_seed(deployer_address);
        let object_address = object::create_object_address(
            &deployer_address, object_seed
        );

        object_code_deployment::publish(deployer, metadata, code);

        object_address
    }

    fun object_seed(publisher: address): vector<u8> {
        let sequence_number = account::get_sequence_number(publisher) + 1;
        let seeds = vector[];
        vector::append(
            &mut seeds,
            bcs::to_bytes(&OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR)
        );
        vector::append(&mut seeds, bcs::to_bytes(&sequence_number));
        seeds
    }

    /// Mock metadata and code for testing
    public fun test_metadata_and_code(): (vector<u8>, vector<vector<u8>>) {

        /*
        [package]
                name = "Mock"
                version = "1.0.0"
                authors = []

                [addresses]
                mock = "_"

                [dev-addresses]
                mock = "0x100"

                [dependencies]

                [dev-dependencies]


        module mock::mock {

            fun init_module(publisher: &signer) {}

            #[test_only]
            public fun init_module_for_testing(publisher: &signer) {
                init_module(publisher);
            }
        }
        */

        // Metadata vector<u8>
        let metadata = vector[
            4u8, 77u8, 111u8, 99u8, 107u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            64u8, 66u8, 52u8, 56u8, 55u8, 68u8, 48u8, 69u8, 65u8, 54u8, 56u8, 56u8, 49u8,
            48u8, 50u8, 53u8, 49u8, 48u8, 51u8, 52u8, 67u8, 66u8, 49u8, 50u8, 48u8, 66u8,
            70u8, 56u8, 68u8, 52u8, 56u8, 66u8, 52u8, 54u8, 68u8, 68u8, 49u8, 68u8, 65u8,
            55u8, 49u8, 54u8, 54u8, 66u8, 53u8, 51u8, 68u8, 67u8, 52u8, 50u8, 52u8, 51u8,
            49u8, 55u8, 56u8, 57u8, 54u8, 57u8, 50u8, 56u8, 69u8, 48u8, 56u8, 66u8, 53u8,
            118u8, 31u8, 139u8, 8u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 255u8, 109u8, 203u8,
            65u8, 10u8, 128u8, 32u8, 16u8, 133u8, 225u8, 253u8, 156u8, 34u8, 220u8, 23u8,
            211u8, 1u8, 58u8, 66u8, 39u8, 16u8, 137u8, 65u8, 135u8, 138u8, 72u8, 197u8,
            41u8, 233u8, 248u8, 41u8, 174u8, 130u8, 182u8, 223u8, 255u8, 158u8, 142u8,
            100u8, 15u8, 90u8, 217u8, 128u8, 167u8, 147u8, 187u8, 169u8, 83u8, 115u8,
            176u8, 135u8, 130u8, 204u8, 73u8, 246u8, 224u8, 43u8, 140u8, 3u8, 14u8, 168u8,
            128u8, 238u8, 107u8, 11u8, 73u8, 138u8, 104u8, 3u8, 160u8, 201u8, 185u8, 196u8,
            34u8, 44u8, 6u8, 206u8, 242u8, 168u8, 195u8, 69u8, 21u8, 119u8, 156u8, 251u8,
            159u8, 134u8, 207u8, 136u8, 216u8, 122u8, 100u8, 239u8, 216u8, 219u8, 189u8,
            230u8, 182u8, 255u8, 218u8, 11u8, 110u8, 36u8, 72u8, 12u8, 147u8, 0u8, 0u8,
            0u8, 1u8, 4u8, 109u8, 111u8, 99u8, 107u8, 124u8, 31u8, 139u8, 8u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 2u8, 255u8, 109u8, 141u8, 75u8, 10u8, 128u8, 48u8, 12u8, 68u8,
            247u8, 61u8, 69u8, 64u8, 16u8, 189u8, 66u8, 61u8, 138u8, 72u8, 65u8, 173u8,
            26u8, 108u8, 83u8, 233u8, 103u8, 33u8, 210u8, 187u8, 107u8, 227u8, 78u8, 156u8,
            69u8, 22u8, 153u8, 55u8, 51u8, 214u8, 205u8, 201u8, 104u8, 176u8, 110u8, 218u8,
            165u8, 44u8, 23u8, 46u8, 33u8, 224u8, 209u8, 146u8, 8u8, 144u8, 48u8, 42u8,
            203u8, 68u8, 115u8, 164u8, 209u8, 96u8, 216u8, 180u8, 151u8, 80u8, 7u8, 92u8,
            73u8, 251u8, 22u8, 174u8, 252u8, 178u8, 85u8, 31u8, 117u8, 136u8, 202u8, 145u8,
            57u8, 7u8, 126u8, 48u8, 60u8, 125u8, 59u8, 212u8, 226u8, 188u8, 42u8, 36u8,
            210u8, 250u8, 223u8, 199u8, 225u8, 162u8, 223u8, 229u8, 182u8, 99u8, 63u8,
            139u8, 44u8, 110u8, 245u8, 55u8, 15u8, 186u8, 183u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8
        ];

        // Code vector<vector<u8>>
        let code = vector[
            vector[
                161u8, 28u8, 235u8, 11u8, 7u8, 0u8, 0u8, 10u8, 7u8, 1u8, 0u8, 2u8, 3u8,
                2u8, 6u8, 5u8, 8u8, 4u8, 7u8, 12u8, 17u8, 8u8, 29u8, 32u8, 16u8, 61u8,
                31u8, 12u8, 92u8, 10u8, 0u8, 0u8, 0u8, 1u8, 0u8, 1u8, 0u8, 1u8, 1u8, 6u8,
                12u8, 0u8, 4u8, 109u8, 111u8, 99u8, 107u8, 11u8, 105u8, 110u8, 105u8,
                116u8, 95u8, 109u8, 111u8, 100u8, 117u8, 108u8, 101u8, 0u8, 0u8, 0u8, 0u8,
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 17u8, 20u8,
                99u8, 111u8, 109u8, 112u8, 105u8, 108u8, 97u8, 116u8, 105u8, 111u8, 110u8,
                95u8, 109u8, 101u8, 116u8, 97u8, 100u8, 97u8, 116u8, 97u8, 9u8, 0u8, 3u8,
                50u8, 46u8, 48u8, 3u8, 50u8, 46u8, 49u8, 0u8, 0u8, 0u8, 0u8, 1u8, 3u8
            ],
            vector[11u8, 0u8, 1u8, 2u8, 0u8]
        ];

        return (metadata, code)
    }
}
