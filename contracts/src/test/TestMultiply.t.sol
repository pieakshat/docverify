// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {MultiplyWithTwo} from "../multiplyTwo.sol";
import {console} from "forge-std/console.sol";
import {IncoTest} from "@inco/lightning/src/test/IncoTest.sol";
import {GWEI} from "@inco/shared/src/TypeUtils.sol"; // 1 GWEI = 1e9
import {euint256, ebool, e} from "@inco/lightning/src/Lib.sol";

contract TestMultiplyWithTwo is IncoTest {
        using e for euint256; 
    MultiplyWithTwo mul; 

    function setUp() public override {
        super.setUp();
        mul = new MultiplyWithTwo();

    }

    function testMultiply() public {
        bytes memory cipher = fakePrepareEuint256Ciphertext(5);

        vm.prank(alice);
        // console.log(cipher);
        (uint256 reqId, euint256 encResult) = mul.multiplyTwoEOA(cipher); 

        processAllOperations();

        assertEq(mul.lastResult(), 10); 
        console.log("Request ID: ", reqId);
        // console.log("Enc result: ", encResult);
    }
}