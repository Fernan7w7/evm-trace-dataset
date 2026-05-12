// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: false
// @precondition: DELETE on critical state reachable without CHECK(authorization) — resolved
// @description: Patched version guards removeBalance with an authorization check.
//               Only the account holder themselves or the contract owner may delete
//               a balance entry.
// @patching_strategy: Added require(msg.sender == user || msg.sender == owner)
//                     before the delete statement

contract SimpleToken_Safe {
    address public owner;
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event BalanceRemoved(address indexed user);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // SAFE: only the account holder or the owner can remove a balance entry
    function removeBalance(address user) external {
        require(msg.sender == user || msg.sender == owner, "not authorized");
        delete balances[user];
        emit BalanceRemoved(user);
    }
}
