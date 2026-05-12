// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.3
// @vulnerable: true
// @precondition: DELEGATECALL to attacker-controlled target with no CHECK(target)
// @description: forward() accepts an arbitrary target address and calldata and
//               delegatecalls it with no validation. An attacker passes their own
//               contract as target — its code executes in this proxy's storage
//               context and can overwrite any storage slot, including owner.
// @patching_strategy: Remove the target parameter; lock the delegatecall target
//                     to a trusted implementation address set by the owner only

contract BareProxy_Vulnerable {
    address public owner;         // slot 0
    address public implementation; // slot 1

    event Forwarded(address indexed target);

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: caller supplies the target — malicious contract runs in this contract's storage context
    function forward(address target, bytes calldata data) external returns (bytes memory) {
        emit Forwarded(target);
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return result;
    }
}
