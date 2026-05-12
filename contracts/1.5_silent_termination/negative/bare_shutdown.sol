// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.5
// @vulnerable: false
// @precondition: SELFDESTRUCT before EMIT — resolved
// @description: Patched version emits ContractDestroyed before selfdestruct,
//               giving off-chain monitors a signal before termination.
// @patching_strategy: Added emit ContractDestroyed(owner, balance) before selfdestruct


contract VaultV1_Safe {
    address public owner;

    event FundsDeposited(address indexed sender, uint256 amount);
    event ContractDestroyed(address indexed owner, uint256 balance);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        emit FundsDeposited(msg.sender, msg.value);
    }

    // SAFE: emit fires before selfdestruct — monitor receives signal
    function shutdown() external onlyOwner {
        emit ContractDestroyed(owner, address(this).balance);
        selfdestruct(payable(owner));
    }
}