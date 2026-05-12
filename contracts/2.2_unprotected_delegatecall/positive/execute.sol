// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.2
// @vulnerable: true
// @precondition: No CHECK(msg.sender) or CHECK(target) before DELEGATECALL
// @description: execute() accepts an arbitrary target and calldata from any caller
//               and delegatecalls it with no guard of any kind. There is no check
//               on who is calling or what the target address is. An attacker passes
//               their own contract as target — it executes in this contract's storage
//               context and can overwrite any slot, including owner.
// @patching_strategy: Add require(msg.sender == owner) before the delegatecall

contract UnguardedExecutor_Vulnerable {
    address public owner;  // slot 0 — can be overwritten via delegatecall

    event Executed(address indexed target);

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: no CHECK(msg.sender), no CHECK(target) — any caller, any target
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        emit Executed(target);
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return result;
    }
}
