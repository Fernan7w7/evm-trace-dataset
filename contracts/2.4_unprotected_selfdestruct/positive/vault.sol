// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.4
// @vulnerable: true
// @precondition: No CHECK(authorization) before SELFDESTRUCT
// @description: Any caller can invoke kill() and destroy the contract,
//               forwarding all ETH to an arbitrary recipient they specify.
//               Users who deposited funds lose everything with no recourse.
// @patching_strategy: Add onlyOwner modifier to kill()

contract EtherVault_Vulnerable {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        totalDeposited -= amount;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    // VULNERABLE: no CHECK(authorization) — any caller can destroy the vault
    // and redirect all deposited ETH to an address they control
    function kill(address payable recipient) external {
        selfdestruct(recipient);
    }
}
