// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.5
// @vulnerable: true
// @precondition: SELFDESTRUCT before EMIT
// @description: Owner can destroy the contract and forward all ETH without
//               emitting any event. Off-chain monitors receive no signal
//               that the contract was terminated.
// @patching_strategy: Emit ContractDestroyed(owner, balance) before selfdestruct

contract VaultV1_Vulnerable {
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

    // VULNERABLE: selfdestruct fires with no preceding emit
    // ContractDestroyed is defined but never called here
    function shutdown() external onlyOwner {
        selfdestruct(payable(owner));
    }
}