#![no_main]

use sha2::{Sha384, Digest};

use risc0_zkvm::guest::env;


use ark_bn254::{Bn254, G1Projective, G2Projective, Fr as ScalarField};
use ark_std::vec::Vec;
use ark_ec::{pairing::Pairing, Group};
use ark_serialize::CanonicalDeserialize;
use ark_ff::PrimeField;

fn compute_merkle_root(leaf: &Vec<u8>, merkle_path: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut current_hash: Vec<u8> = Sha384::digest(leaf).to_vec();

    for sibling in merkle_path {
        let mut hasher = Sha384::new();
        if current_hash < *sibling {
            hasher.update(&current_hash);
            hasher.update(&sibling);
        } else {
            hasher.update(&sibling);
            hasher.update(&current_hash);
        }
        current_hash = hasher.finalize().to_vec();
    }

    current_hash
}

risc0_zkvm::guest::entry!(main);
fn main() {
    let start = env::cycle_count();

    let (pubkey_bytes, merkle_root, signature_bytes): (Vec<u8>, Vec<u8>, Vec<u8>) = env::read();

    let leaf_hash: Vec<u8> = env::read();
    let merkle_path: Vec<Vec<u8>> = env::read();

    let computed_root = compute_merkle_root(&leaf_hash, &merkle_path);

    assert_eq!(computed_root, merkle_root);

    let diff = env::cycle_count();
    env::log(&format!("cycle count after merkle root: {}", diff - start));

    let pubkey: G2Projective = G2Projective::deserialize_compressed(&mut &pubkey_bytes[..]).unwrap();
    let signature: G1Projective = G1Projective::deserialize_compressed(&mut &signature_bytes[..]).unwrap();

    let g2_gen: G2Projective = G2Projective::generator();
    let g1_gen: G1Projective = G1Projective::generator();
    let field_element_from_hash = ScalarField::from_le_bytes_mod_order(computed_root.as_slice());
    let message: G1Projective = g1_gen * field_element_from_hash;

    let pairing_message_public_key = Bn254::pairing(message, pubkey);
    let pairing_signature_g2_gen = Bn254::pairing(signature, g2_gen);

    assert_eq!(pairing_message_public_key, pairing_signature_g2_gen);

    env::commit(&(signature_bytes, merkle_root));

    let diff = env::cycle_count();
    env::log(&format!("total cycle count: {}", diff - start));
}