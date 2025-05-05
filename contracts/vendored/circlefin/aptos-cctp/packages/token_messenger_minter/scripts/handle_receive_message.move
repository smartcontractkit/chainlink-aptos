script {
    use message_transmitter::message_transmitter;
    use token_messenger_minter::token_messenger;

    fun handle_receive_message(caller: &signer,
                               message: vector<u8>,
                               attestation: vector<u8>) {
        let receipt = message_transmitter::receive_message(
            caller,
            &message,
            &attestation
        );
        token_messenger::handle_receive_message(receipt);
    }
}
