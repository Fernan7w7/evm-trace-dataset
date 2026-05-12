// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.3
// @vulnerable: true
// @precondition: DELEGATECALL to attacker-controlled target with no CHECK(target)
// @description: Storage layout mismatch between proxy and logic contract. The proxy
//               stores owner at slot 0 and totalFunds at slot 1. The logic contract
//               stores registryName at slot 0 and registryOwner at slot 1. When the
//               proxy delegatecalls the logic and the logic writes to registryOwner
//               (slot 1), it overwrites the proxy's totalFunds slot. When the logic
//               writes to registryName (slot 0), it overwrites the proxy's owner slot.
//               An attacker calls setRegistryName(attackerAsBytes32) through the proxy
//               to silently replace the proxy's owner with their own address.
//               Neither contract is itself malicious — the collision is purely
//               structural, making it the hardest variant to detect.
// @patching_strategy: Prepend the proxy's reserved storage fields (owner, totalFunds,
//                     logic) to the logic contract's layout so registry-specific
//                     variables begin at a slot beyond what the proxy uses

// Logic contract — legitimate registry code, unaware of the proxy's layout
// Slot 0: bytes32 registryName  ← collides with proxy slot 0 (address owner)
// Slot 1: address registryOwner ← collides with proxy slot 1 (uint256 totalFunds)
contract RegistryLogic_Vulnerable {
    bytes32 public registryName;   // slot 0
    address public registryOwner;  // slot 1

    event NameUpdated(bytes32 indexed newName);
    event OwnerUpdated(address indexed newOwner);

    // When called via proxy delegatecall: writes to slot 0 → overwrites proxy.owner
    function setRegistryName(bytes32 newName) external {
        registryName = newName;
        emit NameUpdated(newName);
    }

    // When called via proxy delegatecall: writes to slot 1 → overwrites proxy.totalFunds
    function setRegistryOwner(address newOwner) external {
        registryOwner = newOwner;
        emit OwnerUpdated(newOwner);
    }
}

// Proxy vault — delegates registry calls to RegistryLogic
// Slot 0: address owner     ← same slot as registryName (bytes32) in logic
// Slot 1: uint256 totalFunds ← same slot as registryOwner (address) in logic
// Slot 2: address logic
contract VaultProxy_Vulnerable {
    address public owner;       // slot 0
    uint256 public totalFunds;  // slot 1
    address public logic;       // slot 2

    mapping(address => uint256) public deposits; // slot 3

    event Deposit(address indexed sender, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _logic) {
        owner = msg.sender;
        logic = _logic;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalFunds += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdrawAll() external onlyOwner {
        uint256 amount = totalFunds;
        totalFunds = 0;
        payable(owner).transfer(amount);
    }

    // VULNERABLE: delegatecalls to a logic contract whose layout collides with this proxy's storage
    fallback() external payable {
        address _logic = logic;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _logic, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
