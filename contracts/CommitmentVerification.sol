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

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.

/// @title A starter application using RISC Zero.
/// @notice This basic application holds a number, guaranteed to be even.
/// @dev This contract demonstrates one pattern for offloading the computation of an expensive
///      or difficult to implement function to a RISC Zero guest running on Bonsai.
contract CommitmentVerification {
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;
    /// @notice Image ID of the only zkVM binary to accept verification from.
    ///         The image ID is similar to the address of a smart contract.
    ///         It uniquely represents the logic of that guest program,
    ///         ensuring that only proofs generated from a pre-defined guest program
    ///         (in this case, checking if a number is even) are considered valid.
    bytes32 public constant imageId = ImageID.MAIN_ID;


    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
    }

    function verify(bytes memory journal, bytes32 postStateDigest, bytes calldata seal) public returns (bool){
        require(verifier.verify(seal, imageId, postStateDigest, sha256(journal)), "verification failed");   
    }
}
