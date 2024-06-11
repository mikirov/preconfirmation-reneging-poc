use bytemuck::cast_slice;
use risc0_zkvm::{compute_image_id, serde::to_vec, Receipt};

use sha2::{Digest, Sha384};

use anyhow::Context;
use ethers::abi::Token;
use std::io::Write;

use alloy_primitives::FixedBytes;
use risc0_ethereum_contracts::groth16::Seal;
use std::time::Duration;

use methods::{MAIN_ELF, MAIN_ID};

use bonsai_sdk::alpha as bonsai_sdk;

use ark_bn254::{Fr as ScalarField, G1Projective, G2Projective};
use ark_ec::Group;
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::UniformRand;

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

fn run_bonsai(
    signature_input: (Vec<u8>, Vec<u8>, Vec<u8>),
    leaf_hash: Vec<u8>,
    merkle_path: Vec<Vec<u8>>,
) -> Result<(Vec<u8>, FixedBytes<32>, Vec<u8>), anyhow::Error> {
    let client = bonsai_sdk::Client::from_env(risc0_zkvm::VERSION)?;

    // Compute the image_id, then upload the ELF with the image_id as its key.
    // let image_id = hex::encode(compute_image_id(MAIN_ELF)?);
    let image_id = compute_image_id(MAIN_ELF).unwrap().to_string();
    tracing::info!("image_id: {}", image_id);
    client.upload_img(&image_id, MAIN_ELF.to_vec())?;

    // Prepare input data and upload it.
    // let input_data = to_vec(&signature_input).unwrap();
    let mut input_data: Vec<u8> = Vec::new();
    input_data.extend_from_slice(cast_slice(&to_vec(&signature_input)?));
    input_data.extend_from_slice(cast_slice(&to_vec(&leaf_hash)?));
    input_data.extend_from_slice(cast_slice(&to_vec(&merkle_path)?));

    let input_id = client.upload_input(input_data)?;
    tracing::info!("uploaded input");
    // Add a list of assumptions
    let assumptions: Vec<String> = vec![];

    // Start a session running the prover
    let session = client.create_session(image_id, input_id, assumptions)?;
    loop {
        let res = session.status(&client)?;
        if res.status == "RUNNING" {
            tracing::info!(
                "Current status: {} - state: {} - continue polling...",
                res.status,
                res.state.unwrap_or_default()
            );
            std::thread::sleep(Duration::from_secs(15));
            continue;
        }
        if res.status == "SUCCEEDED" {
            // Download the receipt, containing the output
            let receipt_url = res
                .receipt_url
                .expect("API error, missing receipt on completed session");

            let receipt_buf = client.download(&receipt_url)?;
            let receipt: Receipt = bincode::deserialize(&receipt_buf)?;
            receipt
                .verify(MAIN_ID)
                .expect("Receipt verification failed");
        } else {
            panic!(
                "Workflow exited: {} - | err: {}",
                res.status,
                res.error_msg.unwrap_or_default()
            );
        }

        break;
    }

    // Optionally run stark2snark
    tracing::info!("Running stark2snark...");

    Ok(run_stark2snark(session.uuid)?)
}

fn run_stark2snark(
    session_id: String,
) -> Result<(Vec<u8>, FixedBytes<32>, Vec<u8>), anyhow::Error> {
    let client = bonsai_sdk::Client::from_env(risc0_zkvm::VERSION)?;

    let snark_session = client.create_snark(session_id)?;
    tracing::info!("Created snark session: {}", snark_session.uuid);
    let snark_receipt = loop {
        let res = snark_session.status(&client)?;
        match res.status.as_str() {
            "RUNNING" => {
                tracing::info!("Current status: {} - continue polling...", res.status,);
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
            "SUCCEEDED" => {
                break res.output.context("No snark generated :(")?;
            }
            _ => {
                panic!(
                    "Workflow exited: {} err: {}",
                    res.status,
                    res.error_msg.unwrap_or_default()
                );
            }
        }
    };

    let snark = snark_receipt.snark;
    tracing::info!("Snark proof!: {snark:?}");

    let seal = Seal::abi_encode(snark).context("Read seal")?;
    let post_state_digest: FixedBytes<32> = snark_receipt
        .post_state_digest
        .as_slice()
        .try_into()
        .context("Read post_state_digest")?;
    let journal = snark_receipt.journal;

    Ok((journal, post_state_digest, seal))
}

fn main() -> Result<(), anyhow::Error> {
    let leaf_data = b"example leaf data";
    let leaf_hash: Vec<u8> = Sha384::digest(leaf_data).to_vec();

    let mut merkle_path: Vec<Vec<u8>> = vec![vec![0; 48]; 32];
    // Fill merkle_path with values from 0 to 31
    for i in 0..32 {
        merkle_path[i][47] = i as u8;
    }

    let computed_root: Vec<u8> = compute_merkle_root(&leaf_hash, &merkle_path);

    let g1_gen: G1Projective = G1Projective::generator();
    let field_element_from_hash = ScalarField::from_le_bytes_mod_order(computed_root.as_slice());
    let message: G1Projective = g1_gen * field_element_from_hash;

    let mut rng = ark_std::test_rng();
    let s1 = ScalarField::rand(&mut rng);

    let g2_gen: G2Projective = G2Projective::generator();
    let pubkey: G2Projective = g2_gen * s1;
    let signature: G1Projective = message * s1;

    let mut pubkey_bytes: Vec<u8> = Vec::new();
    pubkey.serialize_compressed(&mut pubkey_bytes).unwrap();

    let mut signature_bytes: Vec<u8> = Vec::new();
    signature
        .serialize_compressed(&mut signature_bytes)
        .unwrap();

    let signature_input = (pubkey_bytes, computed_root, signature_bytes);

    let (journal, post_state_digest, seal) = run_bonsai(signature_input, leaf_hash, merkle_path)?;

    let calldata = vec![
        Token::Bytes(journal),
        Token::FixedBytes(post_state_digest.to_vec()),
        Token::Bytes(seal),
    ];
    let output = hex::encode(ethers::abi::encode(&calldata));

    // Forge test FFI calls expect hex encoded bytes sent to stdout
    print!("{output}");
    std::io::stdout()
        .flush()
        .context("failed to flush stdout buffer")?;

    Ok(())
}
