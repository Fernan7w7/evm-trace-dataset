// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 2.2
// @vulnerable: false
// @precondition: No CHECK(msg.sender) before the write that controls the DELEGATECALL target — resolved
// @description: Patched version restricts registerLib() to the owner. No external
//               caller can replace the library address mapping, so the delegatecall
//               target in executeOp() is always an address the owner approved.
// @patching_strategy: Added onlyOwner modifier to registerLib()

contract DelegateRouter_Safe {
    address public owner;
    mapping(bytes32 => address) public libs;

    event LibRegistered(bytes32 indexed name, address lib);
    event OpExecuted(bytes32 indexed name);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // SAFE: only the owner can register or replace library addresses
    function registerLib(bytes32 name, address lib) external onlyOwner {
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
