// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.4
// @vulnerable: false
// @precondition: No CHECK(authorization) before SELFDESTRUCT — resolved
// @description: Patched version restricts kill() to the contract owner via the
//               existing onlyOwner modifier. The selfdestruct call itself is
//               unchanged — the fix is purely an authorization check, not an
//               event emission. (Contrast with 1.5, where the fix adds an emit
//               before selfdestruct; here the precondition is a missing guard,
//               not a missing signal.)
// @patching_strategy: Added onlyOwner modifier to kill()

contract EtherVault_Safe {
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

    // SAFE: onlyOwner modifier gates the selfdestruct — arbitrary callers are rejected
    function kill(address payable recipient) external onlyOwner {
        selfdestruct(recipient);
    }
}
