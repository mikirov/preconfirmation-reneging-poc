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

import { Sha2Ext } from "./Sha2Ext.sol";

contract CommitmentVerificationTest is RiscZeroCheats, Test {
    CommitmentVerification public commitmentVerification;

    bytes journal;
    bytes32 post_state_digest;
    bytes seal;

    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();
        commitmentVerification = new CommitmentVerification(verifier);

        string[] memory imageRunnerInput = new string[](3);
        uint256 i = 0;
        imageRunnerInput[i++] = "cargo";
        imageRunnerInput[i++] = "run";
        imageRunnerInput[i++] = "--release";
        (journal, post_state_digest, seal) =
            abi.decode(vm.ffi(imageRunnerInput), (bytes, bytes32, bytes));

    }

    function test_works() public {
        //bytes memory leafData = "example leaf data";
        //(bytes32 b1, bytes16 b2) = Sha2Ext.sha384(leafData);
        //bytes memory leaf = abi.encode(b1, b2);
        //console2.logBytes(leaf);
        //48 bytes sha384 of b"example leaf data"

        // bytes[] memory merklePath = new bytes[](32);
        // for (uint256 i = 0; i < 32; i++) {
        //     bytes memory element = new bytes(48);
        //     assembly {
        //         mstore(add(add(element, 48), 0), i) // Store index value at the beginning of the bytes element
        //     }
        //     merklePath[i] = element;
        //     input = bytes.concat(input, merklePath[i]);
        // }

        
        //Values taken from methods/receipt.json after running the "cargo test" proof generation pipeline
        // (bytes memory computedMerkleRoot, bytes memory computedLeaf, bytes memory computedPubkey, bytes memory computedSignature) = abi.decode(journal, (bytes, bytes, bytes, bytes));

        // require(compareBytes(computedMerkleRoot, merkleRoot), "merkle roots don't match");

        // require(compareBytes(computedLeaf, leaf), "leaf doesn't match");

        // require(compareBytes(computedPubkey, blsPubKey), "pubKey doesn't match");

        // require(compareBytes(computedSignature, blsSignature), "signature doesn't match");

        commitmentVerification.verify(journal, post_state_digest, seal);
    }
}

function compareBytes(bytes memory a, bytes memory b) pure returns (bool) {
    if(a.length != b.length) {
        return false;
    }
    for(uint i=0; i<a.length; i++) {
        if(a[i] != b[i]) {
            return false;
        }
    }
    return true;
}