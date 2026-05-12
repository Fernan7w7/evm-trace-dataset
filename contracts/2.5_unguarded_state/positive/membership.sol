// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: true
// @precondition: DELETE on critical state reachable without CHECK(authorization)
// @description: Anyone can call removeMember(address) to delete an entire Member
//               struct in one operation — simultaneously zeroing role, joinDate,
//               votingPower, and the active flag. The single delete is more
//               destructive than any individual field write because all four
//               pieces of critical state are wiped atomically and irreversibly.
// @patching_strategy: Add require(msg.sender == owner) before the delete
//                     statement in removeMember

contract MemberRegistry_Vulnerable {
    address public owner;

    struct Member {
        uint8  role;         // 0=none, 1=basic, 2=moderator, 3=admin
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

    // VULNERABLE: no CHECK(authorization) — any caller can wipe any member's full struct
    function removeMember(address account) external {
        require(members[account].active, "not a member");
        delete members[account]; // zeroes role, joinDate, votingPower, active simultaneously
        memberCount--;
        emit MemberRemoved(account);
    }
}
