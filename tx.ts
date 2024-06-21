import { ethers } from "ethers";
import { assert } from "chai";
import * as dotenv from "dotenv";

import * as path from 'path';


import {
    BYTES_PER_BLOB,
    Blob,
    Bytes48,
    blobToKzgCommitment,
    computeBlobKzgProof,
    loadTrustedSetup,
    verifyBlobKzgProof
  } from "c-kzg";
  

dotenv.config();

assert(process.env.OWNER_PK !== undefined, "OWNER_PK is undefined");
assert(process.env.RPC_URL !== undefined, "RPC_URL is undefined");

const ownerPrivateKey: string = process.env.OWNER_PK!;
const rpcUrl: string = process.env.RPC_URL!;

// Setup provider, wallet
const provider: ethers.providers.JsonRpcProvider = new ethers.providers.JsonRpcProvider(rpcUrl);
const signer: ethers.Wallet = new ethers.Wallet(ownerPrivateKey, provider);

async function generateType2SignedTransaction(to: string, nonce: number, feeData: ethers.providers.FeeData, chainId: number) {
    const tx: ethers.providers.TransactionRequest = {
        type: 2,
        to,
        value: ethers.utils.parseEther("0.1"), // Adjust the value as needed
        gasLimit: 21000,
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas ?? undefined,
        maxFeePerGas: feeData.maxFeePerGas ?? undefined,
        nonce,
        chainId
    };

    const signedTx = await signer.signTransaction(tx);
    return signedTx;
}

async function sendRawTransaction() {
    const from: string = await signer.getAddress();
    const to: string = await ethers.Wallet.createRandom().getAddress();
    const nonce: number = await provider.getTransactionCount(from, 'pending');
    const chainId: number = await signer.getChainId();
    const feeData: ethers.providers.FeeData = await provider.getFeeData();

    // Generate type 2 signed transactions to fill the blob
    const signedTransactions: Buffer[] = [];

    let totalLength = 0;
    while (totalLength < BYTES_PER_BLOB) {
        const signedTx = await generateType2SignedTransaction(to, nonce + signedTransactions.length, feeData, chainId);
        const txBuffer = Buffer.from(signedTx.slice(2), 'hex'); // Remove the '0x' prefix
        const txLength = txBuffer.length; // Calculate length in bytes

        // Check if adding the new transaction would exceed the blob size
        if (totalLength + txLength > BYTES_PER_BLOB) {
            break;
        }

        signedTransactions.push(txBuffer);
        totalLength += txLength;
    }

    // Create a buffer of exactly BYTES_PER_BLOB bytes
    let transactionBlob = Buffer.concat(signedTransactions, BYTES_PER_BLOB);

    // Ensure the buffer size is correct
    if (transactionBlob.length !== BYTES_PER_BLOB) {
        throw new Error(`Buffer size is incorrect: ${transactionBlob.length} bytes instead of ${BYTES_PER_BLOB} bytes`);
    }

    // Load trusted setup
    loadTrustedSetup("trusted_setup.txt");

    // Try converting the blob to commitment
    try {
        const commitment = blobToKzgCommitment(transactionBlob);
        const proof = computeBlobKzgProof(transactionBlob, commitment);
        const isValid = verifyBlobKzgProof(transactionBlob, commitment, proof);

        console.log(`Commitment: ${commitment}`);
        console.log(`Proof: ${proof}`);
        console.log(`Is valid: ${isValid}`);
        console.log("0x01" + ethers.utils.sha256(commitment).substr(4, 64)); // versioned hash

        const txPayloadBody = {
            chainId: ethers.utils.hexlify(chainId),
            nonce: ethers.utils.hexlify(nonce),
            maxPriorityFeePerGas: ethers.utils.hexlify(feeData.maxPriorityFeePerGas ?? 0),
            maxFeePerGas: ethers.utils.hexlify(feeData.maxFeePerGas ?? 0),
            gasLimit: ethers.utils.hexlify(250000),
            to,
            value: "0x",
            data: "0x",
            accessList: [],
            maxFeePerBlobGas: ethers.utils.hexlify(10000000),
            blobVersionedHashes: ["0x01" + ethers.utils.sha256(commitment).substr(4, 64)]
        };
        console.log(txPayloadBody);

        const rlpEncodedPayload = ethers.utils.RLP.encode(Object.values(txPayloadBody));
        console.log(rlpEncodedPayload);

        const BLOB_TX_TYPE = '0x03'; // source https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md
        const payloadForHashing = BLOB_TX_TYPE + rlpEncodedPayload.slice(2);
        console.log(payloadForHashing);

        // Calculate the digest
        const digest = ethers.utils.keccak256(payloadForHashing);
        const signature = await signer.signMessage(ethers.utils.arrayify(digest));
        const { r, s, v } = ethers.utils.splitSignature(signature);

        let signedTransaction = {
            ...txPayloadBody,
            y_parity: "0x0" + (v - 27),
            r: ethers.utils.hexZeroPad(r, 32),
            s: ethers.utils.hexZeroPad(s, 32),
        };
        console.log(signedTransaction);

        // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md#networking
        const networkRepresentation = ethers.utils.RLP.encode([Object.values(signedTransaction), [transactionBlob], [commitment], [proof]]);
        console.log(networkRepresentation.length);

        const txHash = await provider.send('eth_sendRawTransaction', [networkRepresentation]);
        return txHash;
    } catch (error) {
        console.error("Error converting blob to commitment:", error);
        throw error;
    }
}

sendRawTransaction()
    .catch(error => console.error(error));
