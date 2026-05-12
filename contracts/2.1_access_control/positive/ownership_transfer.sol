// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.1
// @vulnerable: true
// @precondition: No CHECK(msg.sender == owner) before WRITE(pendingOwner)
// @description: Two-step ownership transfer pattern where the first step —
//               initiateTransfer() — has no onlyOwner guard. Any caller can
//               nominate themselves as pendingOwner, then immediately call
//               acceptOwnership() to complete the takeover. The pattern looks
//               secure at a glance because acceptOwnership() is correctly guarded
//               — the missing check is one step earlier.
// @patching_strategy: Add onlyOwner modifier to initiateTransfer()

contract OwnedContract_Vulnerable {
    address public owner;
    address public pendingOwner;

    event OwnershipTransferInitiated(address indexed newOwner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: no CHECK(msg.sender == owner) — any caller can set pendingOwner to themselves
    function initiateTransfer(address newOwner) external {
        require(newOwner != address(0), "zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(newOwner);
    }

    // Correctly guarded — but this check alone is not enough if step one is open
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function sensitiveAction() external onlyOwner {
        // privileged operation — reachable by anyone who completes the two-step takeover
    }
}
