// SPDX-License-Identifier: MIT
pragma solidity ^0.8;


import {euint256, ebool, e} from "@inco/lightning/src/Lib.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {EIP712}  from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA}  from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Verify is Ownable, EIP712 {
    using e for *; 

    struct Info { address owner; euint256 timestamp; } // struct to hold the document info

    mapping(bytes32 => Info) public docs; // mapiping of document hashes to info of each document  
    mapping(address => uint256) public nonces;       // replay-protection

    event DocumentAccepted(bytes document, address owner);

    constructor() EIP712("DocAnchor", "1") Ownable(msg.sender){}

    bytes32 private constant _TYPE_HASH = keccak256("Anchor(bytes32 root, address owner, uint256 nonce, uint256 deadline)"
    ); 

    function _hash(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b)); 
    }


    function anchorWithSig(
        bytes32 root, 
        address owner, 
        uint256 deadline, 
        uint8 v, bytes32 r, bytes32 s
        ) external {
        require(block.timestamp <= deadline, "Signature expired");
        // require(docs[root].timestamp == uint256(0), "Document already exists"); 

        uint256 nonce = nonces[owner]++; 

        bytes32 structHash = keccak256(abi.encode(
            _TYPE_HASH, 
            root, 
            owner, 
            nonce, 
            deadline
        ));

        bytes32 digest = _hashTypedDataV4(structHash);

        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner, "Invalid signature"); 

        docs[root] = Info({
            owner: owner,
            timestamp: e.asEuint256(block.timestamp)
        });
        emit DocumentAccepted(abi.encode(root), owner);
    }

    /**
     * @param rootHash      The Merkle root you expect.
     * @param encryptedLeaf      The hash of the target page (same hashing scheme as tree).
     * @param encryptedProof     Array of sibling hashes, depth-first from leaf → root.
     * @param isLeft    `true` if the sibling is on the *left* of the current node (i.e. concat = sibling⧺current).
     *                  Must be the same length as `proof`.
     * @return ok       True if the reconstructed root equals `root`.
     */
function verify(
    bytes32 rootHash, 
    bytes memory encryptedLeaf,
    bytes[] memory encryptedProof,
    bool[] calldata isLeft
) external returns (ebool) {
    
    require(docs[rootHash].owner == address(0), "Document already exists");
    require(encryptedProof.length == isLeft.length, "Length mismatch");
    
    euint256 computed = e.newEuint256(encryptedLeaf, msg.sender);
    
    for (uint256 i = 0; i < encryptedProof.length; i++) {
        euint256 proofElement = e.newEuint256(encryptedProof[i], msg.sender);
        // Use appropriate encrypted operations here
        computed = e.select(
            e.asEbool(isLeft[i]),
            e.combine(proofElement, computed),
            e.combine(computed, proofElement)
        );
    }
    
    return e.eq(computed, e.asEuint256(uint256(rootHash)));
}
}