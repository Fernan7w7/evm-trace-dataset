// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: false
// @precondition: DELETE on critical state reachable without CHECK(authorization) — resolved
// @description: Patched version restricts removeMember to the contract owner via
//               an onlyOwner modifier. The struct delete is now only reachable
//               through an authorized call path.
// @patching_strategy: Applied the existing onlyOwner modifier to removeMember,
//                     replacing the unguarded external visibility

contract MemberRegistry_Safe {
    address public owner;

    struct Member {
        uint8  role;
        uint64 joinDate;
        uint96 votingPower;
        bool   active;
    }

    mapping(address => Member) public members;
    uint256 public memberCount;

    event MemberAdded(address indexed account, uint8 role);
    event MemberRemoved(address indexed account);
    event RoleUpdated(address indexed account, uint8 newRole);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addMember(address account, uint8 role) external onlyOwner {
        require(!members[account].active, "already a member");
        members[account] = Member({
            role:        role,
            joinDate:    uint64(block.timestamp),
            votingPower: 100,
            active:      true
        });
        memberCount++;
        emit MemberAdded(account, role);
    }

    function updateRole(address account, uint8 newRole) external onlyOwner {
        require(members[account].active, "not a member");
        members[account].role = newRole;
        emit RoleUpdated(account, newRole);
    }

    // SAFE: onlyOwner modifier gates the struct delete
    function removeMember(address account) external onlyOwner {
        require(members[account].active, "not a member");
        delete members[account];
        memberCount--;
        emit MemberRemoved(account);
    }
}
