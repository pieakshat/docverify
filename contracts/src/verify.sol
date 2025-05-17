// SPDX-License-Identifier: MIT
pragma solidity ^0.8;


import {euint256, ebool, e} from "@inco/lightning/src/Lib.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {EIP712}  from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA}  from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Verify is Ownable, EIP712 {
    using e for euint256; 
    using e for bytes; 
    using e for uint256; 
    using e for address; 

    struct Info { address owner; uint256 timestamp; } // struct to hold the document info

    mapping(bytes32 => Info) public docs; // mapiping of document hashes to info of each document  
    mapping(address => uint256) public nonces;       // replay-protection

    event DocumentAccepted(bytes document, address owner);

    constructor() EIP712("DocAnchor", "1") {}

    bytes32 private constant _TYPE_HASH = keccak256("Anchor(bytes32 root, address owner, uint256 nonce, uint256 deadline)"
    ); 


    function anchorWithSig(
        bytes32 root, 
        address owner, 
        uint256 deadline, 
        uint8 v, bytes32 r, bytes32 s
        ) external {
        require(block.timestamp <= deadline, "Signature expired");
        require(docs[root].timestamp == uint256(0), "Document already exists"); 

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
            timestamp: block.timestamp
        });
        emit DocumentAccepted(root, owner);
    }
}