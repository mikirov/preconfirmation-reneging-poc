include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {

    use risc0_zkvm::{default_executor, ExecutorEnv, default_prover};

    use sha3::{Keccak256, Digest};
    use sha2::{Sha256};

    use anyhow::Result;

    use ed25519_dalek::{Signature, Signer, SigningKey};
    use rand::rngs::OsRng;

    fn versioned_hash(data: Vec<Vec<u8>>) -> Vec<u8> {
        let mut hasher = Sha256::new();
    
        // Iterate over the vector of vectors, updating the hash for each inner vector
        for bytes in data {
            hasher.update(bytes);
        }
    
        // Finalize the hash
        let mut result = hasher.finalize().to_vec();
    
        // Modify the first byte of the hash
        if !result.is_empty() {
            result[0] = 0x01;
        }
    
        result
    }

    #[test]
    fn test_execute_success() -> Result<(), anyhow::Error> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .init();        

        let mut blob: Vec<Vec<u8>> = Vec::new();
        // for mock purposes transactions are exactly 32 bytes long and 4096 transactions fit in a blob
        for i in 0..4096 {
            let tx: Vec<u8> = vec![i as u8; 32];
            blob.push(tx);
        }
    
        let versioned_hash: Vec<u8> = versioned_hash(blob.clone());

        let tx_non_existent: Vec<u8> = vec![0; 64]; // mock. will not result in the same hash as any of the above since the length is different
    
        let block_number: u32 = 1234; // mock
    
        let mut hasher = Keccak256::new();
        hasher.update(&tx_non_existent);
        let tx_hash: Vec<u8> = hasher.finalize().to_vec();
    
        let mut hasher2 = Keccak256::new();
        hasher2.update(&tx_hash);
        hasher2.update(&block_number.to_le_bytes());
        let commitment: Vec<u8> = hasher2.finalize().to_vec();
    
        let mut csprng = OsRng {};
        let keypair: SigningKey = SigningKey::generate(&mut csprng);
        let signature: Signature = keypair.sign(&commitment);
    
        // tracing::info!("env");
        let vk = keypair.verifying_key();
        let inputs: ([u8; 32], Vec<u8>, Vec<u8>, u32, Vec<u8>, Vec<Vec<u8>>) = (vk.to_bytes(), signature.to_vec(), tx_hash, block_number, versioned_hash, blob);
        
        tracing::info!("test");
        let env: ExecutorEnv = ExecutorEnv::builder()
            .write(&inputs)
            .unwrap()
            .build()
            .unwrap();

        // let session = default_executor().execute(env, super::MAIN_ELF).unwrap();
        let receipt = default_prover().prove(env, super::MAIN_ELF).unwrap();
        receipt.verify(super::MAIN_ID).unwrap();
        
        Ok(())
    }
}
