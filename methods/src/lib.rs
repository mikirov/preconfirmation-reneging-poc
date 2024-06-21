include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {

    use risc0_zkvm::{default_executor, ExecutorEnv, default_prover};

    use sha3::{Keccak256, Digest};

    use anyhow::Result;

    use k256::{
        ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
        EncodedPoint,
    };

    use hex_literal::hex; // Ensure you have `hex_literal` in your `Cargo.toml` for the `hex!` macro

    #[test]
    fn test_execute_success() -> Result<(), anyhow::Error> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .init();        

        let mut sequenced_data: Vec<Vec<u8>> = Vec::new();
        // for mock purposes transactions are exactly 32 bytes long and 4096 transactions fit in a blob
        for i in 1..50 {
            let tx: Vec<u8> = vec![i as u8; 96];
            sequenced_data.push(tx);
        }
    
        // mock. None of the hashes of the mock bytes in the sequence above evaluate to 32 zero bytes
        let tx_hash_non_existent: Vec<u8> = vec![0; 32];
    
        let mut block_number: Vec<u8> = vec![0; 32]; // mock
        block_number[31] = 5; // mock
    
        let mut hasher = Keccak256::new();
        hasher.update(&tx_hash_non_existent);
        hasher.update(&block_number);
        let commitment: Vec<u8> = hasher.finalize().to_vec();
    
        // Generate a secp256k1 keypair and sign the message.
        let signing_key = SigningKey::from_bytes(&hex!("0000000000000000000000000000000000000000000000000000000000001234").into())?;

        // Sign the commitment
        let signature: Signature = signing_key.sign(&commitment);

        // Prepare output information
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(true); // Compressed form
        let signature_bytes = signature.to_vec();

        // You can now use these values as needed
        tracing::info!("Public Key: {:?}", encoded_point);
        tracing::info!("Signature: {:?}", signature_bytes);
            
        // tracing::info!("env");
        let inputs: (EncodedPoint, Signature, Vec<u8>, Vec<u8>, Vec<Vec<u8>>) = (encoded_point, signature, tx_hash_non_existent, block_number, sequenced_data);
        
        tracing::info!("test");
        let env: ExecutorEnv = ExecutorEnv::builder()
            .write(&inputs)
            .unwrap()
            .build()
            .unwrap();

        let session = default_executor().execute(env, super::MAIN_ELF).unwrap();
        // let receipt = default_prover().prove(env, super::MAIN_ELF).unwrap();
        // receipt.verify(super::MAIN_ID).unwrap();
        
        Ok(())
    }
}
