// SPDX-License-Identifier: No License
pragma solidity ^0.8;

import {euint256, ebool, e} from "@inco/lightning/src/Lib.sol";

contract MultiplyWithTwo {
    using e for euint256; 
    using e for uint256;
    using e for bytes; 

    // stores the result of last callback
    uint256 public lastResult;

    function multiplyTwo(euint256 a) external returns (euint256) {
        uint256 two = 2; 
        return a.mul(two.asEuint256());
    }

    function multiplyTwoScalar(euint256 a) external returns (euint256) {
        uint256 two = 2; 
        return a.mul(two);
    }

    function multiplyTwoEOA(bytes memory uint256EInput) external returns(uint256, euint256) {
        euint256 value = uint256EInput.newEuint256(msg.sender); 
        euint256 result = this.multiplyTwo(value); 
        e.allow(result, address(this));
        e.allow(result, msg.sender);
        uint256 requestId = e.requestDecryption(
            result,
            this.callback.selector,
            ""
        );
        return (requestId, result);
    }

    function callback(
        uint256,
        uint256 result,
        bytes memory
    ) external {
        lastResult = result;
    }
}