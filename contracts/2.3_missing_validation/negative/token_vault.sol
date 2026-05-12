// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.3
// @vulnerable: false
// @precondition: No CHECK(address != 0) before WRITE(token) on critical init parameter — resolved
// @description: Patched version adds a zero-address check in both the constructor
//               and setToken(). Attempting to deploy or update with address(0)
//               reverts immediately rather than silently bricking the vault.
// @patching_strategy: Added require(tokenAddress != address(0)) in constructor
//                     and in setToken()

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TokenVault_Safe {
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

    // SAFE: zero-address check prevents silent bricking at deployment
    constructor(address tokenAddress) {
        require(tokenAddress != address(0), "zero token address");
        owner = msg.sender;
        token = IERC20(tokenAddress);
    }

    // SAFE: zero-address check also on the admin update path
    function setToken(address tokenAddress) external onlyOwner {
        require(tokenAddress != address(0), "zero token address");
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
