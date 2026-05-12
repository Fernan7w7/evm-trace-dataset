// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.3
// @vulnerable: true
// @precondition: No CHECK(address != 0) before WRITE(token) on critical init parameter
// @description: The token address can be set to address(0) in the constructor or
//               updated to address(0) via setToken(). No zero-address check exists
//               on either path. If deployed with address(0) or updated to it, all
//               token operations silently target the zero address — deposits and
//               withdrawals will fail or behave unexpectedly, and any ETH or tokens
//               already in the vault become permanently locked.
// @patching_strategy: Add require(tokenAddress != address(0)) in the constructor
//                     and in setToken() before the WRITE to token

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TokenVault_Vulnerable {
    address public owner;
    IERC20  public token;

    mapping(address => uint256) public deposits;
    uint256 public totalDeposited;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event TokenUpdated(address indexed newToken);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // VULNERABLE: no CHECK(tokenAddress != address(0)) — deployer can silently brick the vault
    constructor(address tokenAddress) {
        owner = msg.sender;
        token = IERC20(tokenAddress);
    }

    // VULNERABLE: admin can also update to address(0) with no guard
    function setToken(address tokenAddress) external onlyOwner {
        token = IERC20(tokenAddress);
        emit TokenUpdated(tokenAddress);
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        deposits[msg.sender] += amount;
        totalDeposited += amount;
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient balance");
        deposits[msg.sender] -= amount;
        totalDeposited -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }
}
