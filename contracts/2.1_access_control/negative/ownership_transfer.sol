// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.1
// @vulnerable: false
// @precondition: No CHECK(msg.sender == owner) before WRITE(pendingOwner) — resolved
// @description: Patched version adds onlyOwner to initiateTransfer(). Only the
//               current owner can nominate a successor. acceptOwnership() is
//               unchanged — the fix is purely a guard on the first step.
// @patching_strategy: Added onlyOwner modifier to initiateTransfer()

contract OwnedContract_Safe {
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

    // SAFE: only the current owner can initiate a transfer
    function initiateTransfer(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function sensitiveAction() external onlyOwner {
        // privileged operation
    }
}
