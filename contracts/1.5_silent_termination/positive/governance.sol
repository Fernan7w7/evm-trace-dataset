// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.5
// @vulnerable: true
// @precondition: SELFDESTRUCT before EMIT
// @description: Emergency killswitch modifier destroys the contract when
//               the emergencyStop flag is active. The selfdestruct fires
//               inside the modifier with no preceding emit — off-chain
//               monitors receive no signal. The vulnerability is invisible
//               at the function level since no SELFDESTRUCT appears in
//               the function body itself.
// @patching_strategy: Emit EmergencyShutdown(triggeredBy, balance) inside
//                     the modifier before the selfdestruct call

contract GovernanceV3_Vulnerable {
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

    // VULNERABLE: when emergencyStop is active, silently destroys contract
    // selfdestruct fires with no preceding emit inside this modifier
    modifier killswitch() {
        if (emergencyStop) {
            selfdestruct(payable(owner)); // no emit before this
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

    // owner activates emergency stop — next killswitch call destroys contract
    function activateEmergencyStop() external onlyOwner {
        emergencyStop = true;
        emit EmergencyStopActivated(msg.sender);
    }

    // two-step ownership transfer
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