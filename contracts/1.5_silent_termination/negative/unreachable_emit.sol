// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.5
// @vulnerable: false
// @precondition: SELFDESTRUCT before EMIT — resolved
// @description: Patched version moves the emit above the selfdestruct call
//               so it actually fires before execution terminates.
// @patching_strategy: Moved emit ContractDestroyed above selfdestruct

contract VaultV2_Safe {
    address public owner;
    mapping(address => uint256) public balances;

    event Deposited(address indexed sender, uint256 amount);
    event Withdrawn(address indexed recipient, uint256 amount);
    event ContractDestroyed(address indexed owner, uint256 remainingBalance);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // SAFE: emit fires before selfdestruct
    // note balance captured before destruction
    function shutdown() external onlyOwner {
        emit ContractDestroyed(owner, address(this).balance);
        selfdestruct(payable(owner));
    }
}