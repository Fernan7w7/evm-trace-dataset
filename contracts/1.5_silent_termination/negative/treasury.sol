// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.5
// @vulnerable: false
// @precondition: SELFDESTRUCT before EMIT — resolved
// @description: Patched version emits EmergencyShutdown before asset
//               transfers and selfdestruct. Off-chain monitors receive
//               a signal with full context — who triggered it, how much
//               ETH and how many tokens were drained — before termination.
// @patching_strategy: Added emit EmergencyShutdown(owner, ethBalance,
//                     tokenBalance) before asset transfers and selfdestruct

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract TreasuryV4_Safe {
    address public owner;
    address public pendingOwner;
    IERC20 public token;
    uint256 public totalDeposited;
    bool public paused;

    event Deposited(address indexed sender, uint256 ethAmount);
    event Withdrawn(address indexed recipient, uint256 ethAmount);
    event TokenWithdrawn(address indexed recipient, uint256 tokenAmount);
    event Paused(address indexed triggeredBy);
    event Unpaused(address indexed triggeredBy);
    event OwnershipTransferInitiated(address indexed newOwner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event EmergencyShutdown(address indexed triggeredBy, uint256 ethBalance, uint256 tokenBalance);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier notPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function deposit() external payable notPaused {
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external onlyOwner notPaused {
        require(address(this).balance >= amount, "insufficient ETH");
        (bool ok,) = owner.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(owner, amount);
    }

    function withdrawToken(uint256 amount) external onlyOwner notPaused {
        require(token.balanceOf(address(this)) >= amount, "insufficient tokens");
        token.transfer(owner, amount);
        emit TokenWithdrawn(owner, amount);
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
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

    // SAFE: emit fires before asset transfers and selfdestruct
    // captures full context at the moment of shutdown
    function emergencyShutdown() external onlyOwner {
        uint256 ethBalance = address(this).balance;
        uint256 tokenBalance = token.balanceOf(address(this));

        // emit first — monitor gets signal before anything moves
        emit EmergencyShutdown(owner, ethBalance, tokenBalance);

        if (tokenBalance > 0) {
            token.transfer(owner, tokenBalance);
        }
        selfdestruct(payable(owner));
    }

    receive() external payable {
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
}