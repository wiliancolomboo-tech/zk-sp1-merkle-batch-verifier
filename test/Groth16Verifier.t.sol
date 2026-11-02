// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Groth16Verifier} from "../contracts/Groth16Verifier.sol";

interface Vm {
    function expectRevert(bytes calldata) external;
}

contract Groth16VerifierTest {
    Groth16Verifier internal verifier;
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant R_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    function test_DeploymentSuccess() public view {
        require(address(verifier) != address(0), "Deploy failed");
    }

    function test_FieldOverflowRevert() public {
        Groth16Verifier.Proof memory dummyProof;
        uint256 invalidRoot = R_MOD + 10;
        uint256 validTotalAmount = 1000000;
        uint256 validLeafEvaluation = 12345;
        uint256 validSubRoot = 67890;

        try verifier.settleWithdrawalBatch(
            dummyProof,
            invalidRoot,
            validTotalAmount,
            validLeafEvaluation,
            validSubRoot
        ) {
            revert("Should have reverted on Field Overflow");
        } catch Error(string memory reason) {
            require(
                keccak256(bytes(reason)) == keccak256(bytes("Field Overflow")),
                "Wrong revert reason"
            );
        }
    }

    function test_TotalAmountFieldOverflowRevert() public {
        Groth16Verifier.Proof memory dummyProof;
        uint256 validRoot = 12345;
        uint256 invalidTotalAmount = R_MOD + 5;
        uint256 validLeafEvaluation = 12345;
        uint256 validSubRoot = 67890;

        try verifier.settleWithdrawalBatch(
            dummyProof,
            validRoot,
            invalidTotalAmount,
            validLeafEvaluation,
            validSubRoot
        ) {
            revert("Should have reverted on Field Overflow");
        } catch Error(string memory reason) {
            require(
                keccak256(bytes(reason)) == keccak256(bytes("Field Overflow")),
                "Wrong revert reason"
            );
        }
    }
}
