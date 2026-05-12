// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.3
// @vulnerable: false
// @precondition: DELEGATECALL to attacker-controlled target with no CHECK(target) — resolved
// @description: Patched version adds an initialized flag to the implementation.
//               initialize() can only execute once. The proxy calls initialize()
//               via delegatecall inside its own constructor, so the flag is set
//               in the proxy's storage before any external caller can reach it.
//               Any subsequent initialize() call on the proxy reverts.
// @patching_strategy: Added bool initialized (slot 2) to ImplementationV1_Safe;
//                     UpgradeableProxy_Safe delegatecalls initialize() in its constructor

// Implementation — one-time initializer guarded by an initialized flag
contract ImplementationV1_Safe {
    address public owner;          // slot 0 — mirrors proxy slot 0
    address public implementation; // slot 1 — mirrors proxy slot 1
    bool private initialized;      // slot 2 — stored in proxy's storage when delegatecalled

    // SAFE: reverts if called a second time — attacker cannot re-initialize the proxy
    function initialize(address _owner) external {
        require(!initialized, "already initialized");
        initialized = true;
        owner = _owner;
    }

    function upgradeTo(address newImpl) external {
        require(msg.sender == owner, "not owner");
        implementation = newImpl;
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}

// Proxy — calls initialize() in constructor so the flag is set before deployment completes
contract UpgradeableProxy_Safe {
    address public owner;          // slot 0
    address public implementation; // slot 1
    // slot 2 is used by ImplementationV1_Safe's initialized bool — proxy need not declare it

    event Upgraded(address indexed newImpl);

    // SAFE: initialize() called here — proxy's owner and initialized slots are set atomically
    constructor(address _impl, address _owner) {
        implementation = _impl;
        (bool success,) = _impl.delegatecall(
            abi.encodeWithSignature("initialize(address)", _owner)
        );
        require(success, "initialization failed");
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
