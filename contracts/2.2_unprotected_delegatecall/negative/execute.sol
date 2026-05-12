// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.2
// @vulnerable: false
// @precondition: No CHECK(msg.sender) or CHECK(target) before DELEGATECALL — resolved
// @description: Patched version gates execute() with an owner check.
//               Only the contract owner can trigger a delegatecall, removing
//               the open entry point that allowed any caller to supply an
//               arbitrary target.
// @patching_strategy: Added require(msg.sender == owner) before the delegatecall

contract UnguardedExecutor_Safe {
    address public owner;

    event Executed(address indexed target);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // SAFE: only the owner can trigger a delegatecall — arbitrary callers are rejected
    function execute(address target, bytes calldata data) external onlyOwner returns (bytes memory) {
        emit Executed(target);
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return result;
    }
}
