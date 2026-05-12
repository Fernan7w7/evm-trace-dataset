// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: true
// @precondition: DELETE on critical state reachable without CHECK(authorization)
// @description: Anyone can call removeBalance(address) to delete another user's
//               balance entry. No authorization check exists on the public entry
//               point — any attacker can reset any victim's balance to zero with
//               a single call.
// @patching_strategy: Add require(msg.sender == user || msg.sender == owner)
//                     before the delete statement

contract SimpleToken_Vulnerable {
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

    // VULNERABLE: no CHECK(authorization) — any caller can wipe any address's balance
    function removeBalance(address user) external {
        delete balances[user];
        emit BalanceRemoved(user);
    }
}
