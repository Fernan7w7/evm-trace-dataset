// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.4
// @vulnerable: false
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(balance) cached before CALL → stale cached value used after CALL — resolved
// @description: Patched version re-reads stakes[msg.sender] after the external call
//               returns, so the yield calculation always uses the current balance
//               regardless of any state changes that occurred during the call.
// @patching_strategy: Moved stakes[msg.sender] READ to after boostCalc.getMultiplier()
//                     returns; removed the pre-call cache entirely

interface IBoostCalculator {
    function getMultiplier(address user) external returns (uint256);
}

contract YieldFarm_Safe {
    address public owner;
    IBoostCalculator public boostCalc;

    mapping(address => uint256) public stakes;

    uint256 public constant BASE_RATE = 1e14;

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

    function adminAdjustStake(address user, uint256 newStake) external onlyOwner {
        stakes[user] = newStake;
    }

    function claimYield() external {
        require(stakes[msg.sender] > 0, "nothing staked");

        // External call happens first — any state changes during this call are reflected below
        uint256 multiplier = boostCalc.getMultiplier(msg.sender);

        // SAFE: READ happens after the external call — always reflects current balance
        uint256 stakedAmount = stakes[msg.sender];
        require(stakedAmount > 0, "stake zeroed during call");

        uint256 yield = (stakedAmount * BASE_RATE * multiplier) / 1e18;
        stakes[msg.sender] = 0;

        (bool ok,) = msg.sender.call{value: yield}("");
        require(ok, "transfer failed");
        emit YieldClaimed(msg.sender, stakedAmount, yield);
    }
}
