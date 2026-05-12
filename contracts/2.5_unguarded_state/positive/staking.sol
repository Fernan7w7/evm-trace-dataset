// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: true
// @precondition: DELETE on critical state reachable without CHECK(authorization)
// @description: unstake(address) is public and delegates to the internal
//               _clearStake(address) which performs the delete. Neither the
//               public entry point nor the internal function checks that
//               msg.sender == user. A per-function analyzer sees logic around
//               the public function and may miss the absent guard because the
//               delete lives one call deeper.
// @patching_strategy: Add require(msg.sender == user) in unstake() before
//                     the call to _clearStake

contract StakingVault_Vulnerable {
    address public owner;

    struct Stake {
        uint256 amount;
        uint256 since;
        bool active;
    }

    mapping(address => Stake) public stakes;
    uint256 public totalStaked;

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function stake() external payable {
        require(msg.value > 0, "zero stake");
        stakes[msg.sender].amount += msg.value;
        stakes[msg.sender].since = block.timestamp;
        stakes[msg.sender].active = true;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    // VULNERABLE: no CHECK(msg.sender == user) — any caller can unstake any address
    function unstake(address user) external {
        require(stakes[user].active, "no active stake");
        uint256 amount = stakes[user].amount;
        _clearStake(user);
        totalStaked -= amount;
        payable(user).transfer(amount);
        emit Unstaked(user, amount);
    }

    // delete lives here — one level below the public entry point
    function _clearStake(address user) internal {
        delete stakes[user];
    }
}
