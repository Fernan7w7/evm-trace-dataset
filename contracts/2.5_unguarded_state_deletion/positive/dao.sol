// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.5
// @vulnerable: true
// @precondition: DELETE on critical state reachable without CHECK(authorization)
// @description: cancelProposal performs a require before the delete, but the
//               check is on existence (proposer != address(0)), not on the
//               caller's identity. A naive "does a CHECK precede DELETE" detector
//               marks this as safe — the function passes the structural pattern
//               but still allows any address to delete any live proposal.
// @patching_strategy: Replace the existence-only require with an authorization
//                     check: require(msg.sender == proposals[id].proposer ||
//                     msg.sender == owner)

contract SimpleDAO_Vulnerable {
    address public owner;

    enum ProposalState { Active, Queued, Executed, Cancelled }

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

    // VULNERABLE: require checks existence, not authorization
    // passes a structural "CHECK before DELETE" test but does not guard the caller
    function cancelProposal(uint256 id) external {
        require(proposals[id].proposer != address(0), "proposal does not exist");
        delete proposals[id];
        emit ProposalCancelled(id);
    }
}
