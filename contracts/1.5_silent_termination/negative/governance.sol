// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.5
// @vulnerable: false
// @precondition: SELFDESTRUCT before EMIT — resolved
// @description: Patched version emits EmergencyShutdown inside the
//               killswitch modifier before the selfdestruct call.
//               Off-chain monitors receive a signal before termination.
// @patching_strategy: Added emit EmergencyShutdown(msg.sender, balance)
//                     before selfdestruct inside the killswitch modifier

contract GovernanceV3_Safe {
    address public owner;
    address public pendingOwner;
    bool public emergencyStop;
    bool public paused;

    mapping(address => bool) public members;
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    struct Proposal {
        address proposer;
        string description;
        uint256 votesFor;
        uint256 votesAgainst;
        bool executed;
        mapping(address => bool) voted;
    }

    event MemberAdded(address indexed member);
    event MemberRemoved(address indexed member);
    event ProposalCreated(uint256 indexed id, address indexed proposer);
    event VoteCast(uint256 indexed id, address indexed voter, bool support);
    event ProposalExecuted(uint256 indexed id);
    event EmergencyStopActivated(address indexed triggeredBy);
    event EmergencyShutdown(address indexed triggeredBy, uint256 balance);
    event OwnershipTransferInitiated(address indexed newOwner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyMember() {
        require(members[msg.sender], "not a member");
        _;
    }

    // SAFE: emits before selfdestruct — monitor receives signal
    modifier killswitch() {
        if (emergencyStop) {
            emit EmergencyShutdown(msg.sender, address(this).balance);
            selfdestruct(payable(owner));
        }
        _;
    }

    constructor() {
        owner = msg.sender;
        members[msg.sender] = true;
    }

    function addMember(address member) external onlyOwner {
        members[member] = true;
        emit MemberAdded(member);
    }

    function removeMember(address member) external onlyOwner {
        members[member] = false;
        emit MemberRemoved(member);
    }

    function createProposal(string calldata description)
        external
        onlyMember
        killswitch
    {
        uint256 id = proposalCount++;
        proposals[id].proposer = msg.sender;
        proposals[id].description = description;
        emit ProposalCreated(id, msg.sender);
    }

    function vote(uint256 id, bool support)
        external
        onlyMember
        killswitch
    {
        Proposal storage p = proposals[id];
        require(!p.voted[msg.sender], "already voted");
        p.voted[msg.sender] = true;
        if (support) {
            p.votesFor++;
        } else {
            p.votesAgainst++;
        }
        emit VoteCast(id, msg.sender, support);
    }

    function executeProposal(uint256 id)
        external
        onlyOwner
        killswitch
    {
        Proposal storage p = proposals[id];
        require(!p.executed, "already executed");
        require(p.votesFor > p.votesAgainst, "did not pass");
        p.executed = true;
        emit ProposalExecuted(id);
    }

    function activateEmergencyStop() external onlyOwner {
        emergencyStop = true;
        emit EmergencyStopActivated(msg.sender);
    }

    function initiateOwnershipTransfer(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    receive() external payable {}
}