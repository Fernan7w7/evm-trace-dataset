// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: false
// @precondition: DELETE on critical state reachable without CHECK(authorization) — resolved
// @description: Patched version replaces the existence-only require with a proper
//               authorization check. Only the original proposer or the contract
//               owner can cancel a proposal — the existence check is retained as
//               a secondary guard but is no longer the sole condition.
// @patching_strategy: Added require(msg.sender == proposals[id].proposer ||
//                     msg.sender == owner) after the existence check in
//                     cancelProposal

contract SimpleDAO_Safe {
    address public owner;

    struct Proposal {
        address  proposer;
        string   description;
        uint256  votesFor;
        uint256  votesAgainst;
        uint256  createdAt;
        bool     queued;
        bool     executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => bool)     public members;
    uint256 public proposalCount;

    event ProposalCreated(uint256 indexed id, address indexed proposer);
    event VoteCast(uint256 indexed id, address indexed voter, bool support);
    event ProposalQueued(uint256 indexed id);
    event ProposalExecuted(uint256 indexed id);
    event ProposalCancelled(uint256 indexed id);
    event MemberAdded(address indexed account);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyMember() {
        require(members[msg.sender], "not a member");
        _;
    }

    constructor() {
        owner = msg.sender;
        members[msg.sender] = true;
    }

    function addMember(address account) external onlyOwner {
        members[account] = true;
        emit MemberAdded(account);
    }

    function createProposal(string calldata description) external onlyMember returns (uint256) {
        uint256 id = proposalCount++;
        proposals[id] = Proposal({
            proposer:     msg.sender,
            description:  description,
            votesFor:     0,
            votesAgainst: 0,
            createdAt:    block.timestamp,
            queued:       false,
            executed:     false
        });
        emit ProposalCreated(id, msg.sender);
        return id;
    }

    function vote(uint256 id, bool support) external onlyMember {
        Proposal storage p = proposals[id];
        require(p.proposer != address(0), "proposal does not exist");
        require(!p.queued && !p.executed, "proposal not active");
        if (support) {
            p.votesFor++;
        } else {
            p.votesAgainst++;
        }
        emit VoteCast(id, msg.sender, support);
    }

    function queueProposal(uint256 id) external onlyOwner {
        Proposal storage p = proposals[id];
        require(p.proposer != address(0), "proposal does not exist");
        require(!p.queued && !p.executed, "already queued or executed");
        require(p.votesFor > p.votesAgainst, "did not pass");
        p.queued = true;
        emit ProposalQueued(id);
    }

    function executeProposal(uint256 id) external onlyOwner {
        Proposal storage p = proposals[id];
        require(p.proposer != address(0), "proposal does not exist");
        require(p.queued && !p.executed, "not queued or already executed");
        p.executed = true;
        emit ProposalExecuted(id);
    }

    // SAFE: existence check retained, authorization check added
    function cancelProposal(uint256 id) external {
        require(proposals[id].proposer != address(0), "proposal does not exist");
        require(
            msg.sender == proposals[id].proposer || msg.sender == owner,
            "not authorized"
        );
        delete proposals[id];
        emit ProposalCancelled(id);
    }
}
