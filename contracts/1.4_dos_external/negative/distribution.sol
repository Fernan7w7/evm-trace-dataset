// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.4
// @vulnerable: false
// @precondition: CALL before state update — recipient revert permanently blocks execution path — resolved
// @description: Patched version removes the require(success) inside the loop.
//               A failed transfer is recorded via TransferFailed and the loop
//               continues to the next recipient. One reverting contract can only
//               forfeit its own share — it cannot prevent distribution to everyone else.
// @patching_strategy: Replaced require(success) with an if (!success) branch that
//                     emits TransferFailed and continues; failed shares remain in
//                     the contract for the owner to handle separately

contract RewardDistributor_Safe {
    address public owner;
    address[] public recipients;

    event RewardAdded(address indexed recipient);
    event Distributed(uint256 totalAmount, uint256 recipientCount);
    event TransferFailed(address indexed recipient, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addRecipient(address recipient) external onlyOwner {
        recipients.push(recipient);
        emit RewardAdded(recipient);
    }

    function recipientCount() external view returns (uint256) {
        return recipients.length;
    }

    // SAFE: failed transfers are skipped — a reverting recipient cannot block the rest
    function distribute() external payable onlyOwner {
        require(recipients.length > 0, "no recipients");
        uint256 share = msg.value / recipients.length;

        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success,) = recipients[i].call{value: share}("");
            if (!success) {
                emit TransferFailed(recipients[i], share); // record, do not revert
            }
        }

        emit Distributed(msg.value, recipients.length);
    }
}
