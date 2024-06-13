#![no_main]

use sha3::{Keccak256, Digest};
use sha2::{Sha256};

use risc0_zkvm::guest::env;

use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use core::hint::black_box;

pub fn verify(verifying_key: VerifyingKey, message: &[u8], signature: Signature) {
    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&message, &signature)
        .expect("Ed25519 signature verification failed");
}

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

risc0_zkvm::guest::entry!(main);
fn main() {
    let start = env::cycle_count();

    env::log(&format!("cycle count start: {}", start));

    let (encoded_verifying_key, signature_bytes, tx_hash, l1_block_number, blob_hash, sequenced_blob): ([u8; 32], Vec<u8>, Vec<u8>, u32, Vec<u8>, Vec<Vec<u8>>) = env::read();

    let diff = env::cycle_count();
    env::log(&format!("cycle count after reading inputs: {}", diff - start));

    let verifying_key = VerifyingKey::from_bytes(&encoded_verifying_key).unwrap();
    let signature: Signature = Signature::from_slice(&signature_bytes).unwrap();

    for sequenced_tx in &sequenced_blob {
        let sequenced_tx_hash: Vec<u8> = Keccak256::digest(sequenced_tx).to_vec();
        assert_ne!(sequenced_tx_hash, tx_hash);
    }

    let versioned_hash: Vec<u8> = versioned_hash(sequenced_blob.clone());
    assert_eq!(versioned_hash, blob_hash);

    let mut hasher = Keccak256::new();
    hasher.update(&tx_hash);
    hasher.update(&l1_block_number.to_le_bytes());
    let commitment: Vec<u8> = hasher.finalize().to_vec();
    // Verify the signature, panicking if verification fails.
    black_box(verify(
        black_box(verifying_key),
        black_box(&commitment),
        black_box(signature),
    ));

    env::commit(&(encoded_verifying_key, signature_bytes, blob_hash));

    let diff = env::cycle_count();
    env::log(&format!("total cycle count: {}", diff - start));
}