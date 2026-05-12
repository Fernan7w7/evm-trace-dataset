// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.2
// @vulnerable: true
// @precondition: No CHECK(msg.sender) before the write that controls the DELEGATECALL target
// @description: A router that delegatecalls named operation libraries. Any caller
//               can invoke registerLib() to replace a library address with an
//               arbitrary contract — there is no CHECK on who can update the
//               registry. The attacker registers their malicious contract under
//               a well-known operation name, then calls executeOp() to trigger
//               the delegatecall. The guard appears to be on executeOp() (library
//               must exist), but the real missing guard is on registerLib().
// @patching_strategy: Add require(msg.sender == owner) to registerLib()

contract DelegateRouter_Vulnerable {
    address public owner;  // slot 0
    mapping(bytes32 => address) public libs; // slot 1

    event LibRegistered(bytes32 indexed name, address lib);
    event OpExecuted(bytes32 indexed name);

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: no CHECK(msg.sender) — any caller can replace any library address
    function registerLib(bytes32 name, address lib) external {
        libs[name] = lib;
        emit LibRegistered(name, lib);
    }

    function executeOp(bytes32 name, bytes calldata data) external returns (bytes memory) {
        address lib = libs[name];
        require(lib != address(0), "unknown operation");
        emit OpExecuted(name);
        (bool success, bytes memory result) = lib.delegatecall(data);
        require(success, "op failed");
        return result;
    }
}
