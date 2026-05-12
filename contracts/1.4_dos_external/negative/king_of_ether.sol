// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.4
// @vulnerable: false
// @precondition: CALL before state update — recipient revert permanently blocks execution path — resolved
// @description: Patched version uses a pull payment pattern. The displaced king's
//               refund is stored in a mapping rather than pushed immediately.
//               A reverting king contract can only harm itself — it simply fails
//               to collect its own refund, but the throne can still change hands.
// @patching_strategy: Replaced the direct ETH push with pendingWithdrawals[previousKing] += previousPot;
//                     added a separate withdraw() function for pull collection

contract KingOfEther_Safe {
    address public king;
    uint256 public pot;
    mapping(address => uint256) public pendingWithdrawals;

    event NewKing(address indexed king, uint256 pot);
    event Withdrawal(address indexed recipient, uint256 amount);

    constructor() payable {
        king = msg.sender;
        pot  = msg.value;
    }

    // SAFE: no ETH push inside claimThrone — a reverting recipient cannot block state advancement
    function claimThrone() external payable {
        require(msg.value > pot, "bid too low");

        pendingWithdrawals[king] += pot; // store refund, do not push
        king = msg.sender;
        pot  = msg.value;

        emit NewKing(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "withdrawal failed");
        emit Withdrawal(msg.sender, amount);
    }
}
