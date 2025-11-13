// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { IRiscZeroVerifier } from "./IRiscZeroVerifier.sol";
import { LibAddress } from "../../../libs/LibAddress.sol";
import { MessageEncodingLib } from "../../../libs/MessageEncodingLib.sol";
import { BaseInputOracle } from "../../../oracles/BaseInputOracle.sol";

/**
 * @notice Boundless Oracle
 * Implements a ZK oracle that allows for efficient verification of intent fulfillment.
 */
contract BoundlessOracle is BaseInputOracle {
    using LibAddress for address;

    /// @dev Address of the ZK verifier
    IRiscZeroVerifier public immutable verifier;
    /// @dev Commitment to the ZK program for verification
    bytes32 public immutable imageId;
    
    constructor(
        IRiscZeroVerifier verifier_,
        bytes32 imageId_
    ) {
        verifier = verifier_;
        imageId = imageId_;
    }

    function verifySettlements(
        uint64 referenceBlockNumber,
        bytes calldata proof,
        uint256 remoteChainId,
        address remoteOracle,
        bytes calldata messageData
    ) external {
        // Get proof validation reference block hash
        bytes32 referenceBlockHash = blockhash(referenceBlockNumber);

        // Get destination chain application and payloads to validate
        (bytes32 application, bytes32[] memory payloadHashes) =
            MessageEncodingLib.getHashesOfEncodedPayloads(messageData);

        // Derive the expected journal
        bytes32 journalDigest = sha256(
            abi.encodePacked(referenceBlockHash, application, payloadHashes)
        );

        // Verify the ZK proof
        verifier.verify(proof, imageId, journalDigest);

        // Mark the payloads as filled
        uint256 numPayloads = payloadHashes.length;
        for (uint256 i = 0; i < numPayloads; i++) {
            bytes32 payloadHash = payloadHashes[i];
            _attestations[remoteChainId][remoteOracle.toIdentifier()][application][payloadHash] = true;

            emit OutputProven(remoteChainId, remoteOracle.toIdentifier(), application, payloadHash);
        }
    }
}