// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {RiscZeroCheats} from "risc0/RiscZeroCheats.sol";
import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {CommitmentVerification} from "../contracts/CommitmentVerification.sol";
import {Elf} from "./Elf.sol"; // auto-generated contract after running `cargo build`.


contract CommitmentVerificationTest is RiscZeroCheats, Test {
    
    // using ECDSA for bytes32;

    CommitmentVerification public commitmentVerification;

    bytes journal;
    bytes32 post_state_digest;
    bytes seal;

    // set up verification contract and start proof
    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();
        commitmentVerification = new CommitmentVerification(verifier);

        // generate proof
        string[] memory imageRunnerInput = new string[](3);
        uint256 i = 0;
        imageRunnerInput[i++] = "cargo";
        imageRunnerInput[i++] = "run";
        imageRunnerInput[i++] = "--release";

        (journal, post_state_digest, seal) = abi.decode(vm.ffi(imageRunnerInput), (bytes, bytes32, bytes));
        console2.logBytes(journal);

    }

    // signature must be ECDSA(keccak256(txHash, last_l1_block_number), it is verified against in the ZK circuit
    function test_success() public {
        //address alice = vm.addr(1234); // private key is the number 1234
        (address alice, uint256 alicePk) = makeAddrAndKey("1234");
        emit log_address(alice);
        //emit log_private_key(alicePk);
        emit log_uint(alicePk);

        uint256 commitment_block_number = 5; // same as the block number constituent of the commitment signature passed as private input in in the host code. See methods/src/main.rs
        bytes32 commitment_tx_hash_non_existent = bytes32(0); // same as the tx hash constituent of the commitment signature passed as private input in in the host code. See methods/src/main.rs

        bytes32 hash = keccak256(abi.encodePacked(commitment_tx_hash_non_existent, commitment_block_number));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        console2.logBytes(signature);
        
        bytes32 publicInputsHash = sha256(signature); // signature is the only public input
        commitmentVerification.verify(publicInputsHash, post_state_digest, seal);
    }

}