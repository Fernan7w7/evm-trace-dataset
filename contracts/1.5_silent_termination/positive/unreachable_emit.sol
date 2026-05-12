// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.5
// @vulnerable: true
// @precondition: SELFDESTRUCT before EMIT
// @description: The shutdown function appears to emit an event before
//               destroying the contract, but the emit appears AFTER the
//               selfdestruct call. Since selfdestruct terminates execution
//               immediately, the emit never fires. Off-chain monitors
//               receive no signal despite the event being defined and
//               seemingly called.
// @patching_strategy: Move emit ContractDestroyed above the selfdestruct call

contract VaultV2_Vulnerable {
    address public owner;
    mapping(address => uint256) public balances;

    event Deposited(address indexed sender, uint256 amount);
    event Withdrawn(address indexed recipient, uint256 amount);
    event ContractDestroyed(address indexed owner, uint256 remainingBalance);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // VULNERABLE: emit appears after selfdestruct — dead code
    // selfdestruct terminates execution immediately
    // ContractDestroyed never fires
    function shutdown() external onlyOwner {
        selfdestruct(payable(owner));
        emit ContractDestroyed(owner, address(this).balance); // unreachable
    }
}