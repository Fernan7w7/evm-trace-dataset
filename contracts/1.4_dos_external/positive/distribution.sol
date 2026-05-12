// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.4
// @vulnerable: true
// @precondition: CALL before state update — recipient revert permanently blocks execution path
// @description: distribute() loops over all recipients and pushes each one's share
//               of ETH in the same transaction. If any recipient is a contract that
//               always reverts on receive, require(success) propagates that revert
//               to the whole call — every other recipient is also blocked. The
//               distribution is permanently bricked as long as that one address
//               remains in the list.
// @patching_strategy: Drop the require(success); emit a TransferFailed event and
//                     continue the loop so one bad recipient cannot block the rest

contract RewardDistributor_Vulnerable {
    address public owner;
    address[] public recipients;

    event RewardAdded(address indexed recipient);
    event Distributed(uint256 totalAmount, uint256 recipientCount);

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

    // VULNERABLE: require(success) inside the loop — one reverting recipient
    // causes the entire distribution to revert, permanently blocking all others
    function distribute() external payable onlyOwner {
        require(recipients.length > 0, "no recipients");
        uint256 share = msg.value / recipients.length;

        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success,) = recipients[i].call{value: share}("");
            require(success, "transfer failed"); // one revert blocks everyone
        }

        emit Distributed(msg.value, recipients.length);
    }
}
