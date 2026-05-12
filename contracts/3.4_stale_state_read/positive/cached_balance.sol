// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.4
// @vulnerable: true
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(balance) cached before CALL → stale cached value used after CALL
// @description: claimYield() caches stakes[msg.sender] in a local variable before
//               making an external call to the boost calculator. If the external
//               call triggers any path that modifies stakes[msg.sender] (e.g. an
//               admin-authorized stake update executed during the callback), the
//               local variable is stale by the time yield is computed. The payout
//               is based on the pre-call balance, not the post-call balance.
// @patching_strategy: Move the stakes[msg.sender] READ to after the external call —
//                     see negative/cached_balance.sol

interface IBoostCalculator {
    // Returns a multiplier (1e18 = 1×). May trigger authorised state changes
    // on external contracts before returning.
    function getMultiplier(address user) external returns (uint256);
}

contract YieldFarm_Vulnerable {
    address public owner;
    IBoostCalculator public boostCalc;

    mapping(address => uint256) public stakes;

    uint256 public constant BASE_RATE = 1e14; // yield per staked token per claim

    event Staked(address indexed user, uint256 amount);
    event YieldClaimed(address indexed user, uint256 stakedAtRead, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _boostCalc) {
        owner     = msg.sender;
        boostCalc = IBoostCalculator(_boostCalc);
    }

    function stake() external payable {
        require(msg.value > 0, "zero stake");
        stakes[msg.sender] += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    // Admin-authorised path — may be called by boostCalc during a callback
    function adminAdjustStake(address user, uint256 newStake) external onlyOwner {
        stakes[user] = newStake;
    }

    function claimYield() external {
        uint256 stakedAmount = stakes[msg.sender]; // READ — cached before external call
        require(stakedAmount > 0, "nothing staked");

        // External call — boostCalc.getMultiplier may invoke adminAdjustStake (or another
        // privileged path) that changes stakes[msg.sender] before returning
        uint256 multiplier = boostCalc.getMultiplier(msg.sender);

        // VULNERABLE: stakedAmount is stale if stakes[msg.sender] changed during the call
        uint256 yield = (stakedAmount * BASE_RATE * multiplier) / 1e18;
        stakes[msg.sender] = 0;

        (bool ok,) = msg.sender.call{value: yield}("");
        require(ok, "transfer failed");
        emit YieldClaimed(msg.sender, stakedAmount, yield);
    }
}
