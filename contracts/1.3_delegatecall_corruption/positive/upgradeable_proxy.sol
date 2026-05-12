// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.3
// @vulnerable: true
// @precondition: DELEGATECALL to attacker-controlled target with no CHECK(target)
// @description: Classic two-step Parity-style proxy takeover. The implementation
//               contract has an initialize() with no guard — anyone can call it
//               at any time. The proxy never calls initialize() in its constructor,
//               leaving its owner slot as address(0). An attacker calls
//               proxy.initialize(attacker), becoming owner. Then calls
//               proxy.upgradeTo(malicious) — the authorization check now passes
//               because the proxy's owner slot is the attacker. All subsequent
//               proxy calls delegatecall into the malicious contract.
// @patching_strategy: Add an initialized flag to initialize(); have the proxy
//                     invoke initialize() inside its own constructor so the flag
//                     is set before any external caller can reach it

// Implementation — deployed standalone, then pointed at by the proxy
contract ImplementationV1 {
    address public owner;          // slot 0 — mirrors proxy slot 0
    address public implementation; // slot 1 — mirrors proxy slot 1

    // VULNERABLE: no initialized guard — can be called by anyone, any number of times
    function initialize(address _owner) external {
        owner = _owner;
    }

    // Only callable by owner — but owner starts as address(0) in the uninitialized proxy
    function upgradeTo(address newImpl) external {
        require(msg.sender == owner, "not owner");
        implementation = newImpl;
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}

// Proxy — all calls fall through to ImplementationV1 via delegatecall
contract UpgradeableProxy_Vulnerable {
    address public owner;          // slot 0 — stays address(0): initialize() never called
    address public implementation; // slot 1

    event Upgraded(address indexed newImpl);

    // VULNERABLE: initialize() is never called — proxy's owner slot stays address(0)
    constructor(address _impl) {
        implementation = _impl;
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
