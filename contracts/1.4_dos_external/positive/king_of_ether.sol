// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.4
// @vulnerable: true
// @precondition: CALL before state update — recipient revert permanently blocks execution path
// @description: Claiming the throne requires pushing ETH to the previous king.
//               If the previous king is a contract whose receive() always reverts,
//               every future bid() call will revert at the push step — nobody can
//               ever become the new king. The throne is permanently frozen at the
//               attacker's address without them needing any ongoing action.
// @patching_strategy: Replace the push with a pull payment — store the displaced
//                     king's refund in a mapping and let them withdraw separately

contract KingOfEther_Vulnerable {
    address public king;
    uint256 public pot;

    event NewKing(address indexed king, uint256 pot);

    constructor() payable {
        king = msg.sender;
        pot  = msg.value;
    }

    // VULNERABLE: ETH is pushed to the current king before state advances
    // A reverting king contract permanently prevents anyone from calling this successfully
    function claimThrone() external payable {
        require(msg.value > pot, "bid too low");

        address previousKing = king;
        uint256 previousPot  = pot;

        king = msg.sender;
        pot  = msg.value;

        // CALL — if previousKing is a contract that always reverts, this line
        // reverts on every future bid, freezing the throne forever
        (bool success,) = previousKing.call{value: previousPot}("");
        require(success, "refund to previous king failed");

        emit NewKing(msg.sender, msg.value);
    }
}
