// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: false
// @precondition: DELETE on critical state reachable without CHECK(authorization) — resolved
// @description: Patched version adds an authorization check at the public entry
//               point before delegating to the internal _clearStake helper.
//               The delete in the internal function is now reachable only by the
//               account holder themselves.
// @patching_strategy: Added require(msg.sender == user) in unstake() before
//                     the call to _clearStake

contract StakingVault_Safe {
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

    // SAFE: caller must be the stake owner before _clearStake is invoked
    function unstake(address user) external {
        require(msg.sender == user, "not authorized");
        require(stakes[user].active, "no active stake");
        uint256 amount = stakes[user].amount;
        _clearStake(user);
        totalStaked -= amount;
        payable(user).transfer(amount);
        emit Unstaked(user, amount);
    }

    function _clearStake(address user) internal {
        delete stakes[user];
    }
}
