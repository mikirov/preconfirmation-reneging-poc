use bytemuck::cast_slice;
use risc0_zkvm::{compute_image_id, serde::to_vec, Receipt};

use sha3::{Keccak256, Digest};
use sha2::{Sha256};

use anyhow::Context;
use ethers::abi::Token;
use std::io::Write;

use alloy_primitives::FixedBytes;

use risc0_ethereum_contracts::groth16::Seal;
use std::time::Duration;

use methods::{MAIN_ELF, MAIN_ID};

use bonsai_sdk::alpha as bonsai_sdk;

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

fn run_bonsai(
    inputs: ([u8; 32], Vec<u8>, Vec<u8>, u32, Vec<u8>, Vec<Vec<u8>>),
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
    input_data.extend_from_slice(cast_slice(&to_vec(&inputs)?));

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

    let (journal, post_state_digest, seal) =  run_bonsai(inputs)?;
        
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
