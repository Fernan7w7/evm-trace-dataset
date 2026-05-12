// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.3
// @vulnerable: false
// @precondition: DELEGATECALL to attacker-controlled target with no CHECK(target) — resolved
// @description: Patched version removes the caller-supplied target parameter.
//               The delegatecall target is locked to the implementation address,
//               which only the owner can update. No external caller can redirect
//               execution to an arbitrary contract.
// @patching_strategy: Removed target parameter from forward(); delegatecall target
//                     is now fixed to the owner-controlled implementation slot

contract BareProxy_Safe {
    address public owner;          // slot 0
    address public implementation; // slot 1

    event Forwarded(address indexed target);
    event ImplementationUpdated(address indexed newImpl);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _impl) {
        owner = msg.sender;
        implementation = _impl;
    }

    function setImplementation(address _impl) external onlyOwner {
        implementation = _impl;
        emit ImplementationUpdated(_impl);
    }

    // SAFE: target is fixed to the trusted implementation — caller cannot redirect to arbitrary code
    function forward(bytes calldata data) external returns (bytes memory) {
        address target = implementation;
        emit Forwarded(target);
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return result;
    }
}
