#![no_main]

use sha3::{Keccak256, Digest};

use risc0_zkvm::guest::env;

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};

risc0_zkvm::guest::entry!(main);
fn main() {
    let start = env::cycle_count();

    env::log(&format!("cycle count start: {}", start));

    let (encoded_verifying_key, signature, tx_hash, l1_block_number, sequenced_data): (EncodedPoint, Signature, Vec<u8>, Vec<u8>, Vec<Vec<u8>>) = env::read();

    let diff = env::cycle_count();
    env::log(&format!("cycle count after reading inputs: {}", diff - start));
    // env::log(&format!("signature bytes length: {}", signature.len()));

    for sequenced_tx in &sequenced_data {
        let sequenced_tx_hash: Vec<u8> = Keccak256::digest(sequenced_tx).to_vec();
        assert_ne!(sequenced_tx_hash, tx_hash);
    }

    let mut hasher = Keccak256::new();
    hasher.update(&tx_hash);
    hasher.update(&l1_block_number);
    let commitment: Vec<u8> = hasher.finalize().to_vec();
    
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&commitment, &signature)
        .expect("ECDSA signature verification failed");


    env::commit(&signature);

    let diff = env::cycle_count();
    env::log(&format!("total cycle count: {}", diff - start));
}