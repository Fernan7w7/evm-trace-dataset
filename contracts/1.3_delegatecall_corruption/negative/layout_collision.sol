// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 1.3
// @vulnerable: false
// @precondition: DELEGATECALL to attacker-controlled target with no CHECK(target) — resolved
// @description: Patched version aligns the logic contract's storage layout with the
//               proxy by prepending the proxy's reserved slots at the top of the
//               logic contract. Registry-specific variables begin at slot 4, safely
//               beyond everything the proxy uses. The same write that collided with
//               proxy.owner in the vulnerable version now writes to a dedicated,
//               isolated slot with no proxy counterpart.
// @patching_strategy: Prepended proxy reserved slots (owner, totalFunds, logic,
//                     deposits) to RegistryLogic_Safe; registry fields shifted to
//                     slots 4 and 5

// Logic contract — storage layout aligned with the proxy
// Slots 0–3: reserved to mirror the proxy's own layout (no writes to these in logic)
// Slot 4: bytes32 registryName   ← no proxy slot at position 4
// Slot 5: address registryOwner  ← no proxy slot at position 5
contract RegistryLogic_Safe {
    // Reserved — mirror proxy slots exactly so delegatecall writes never collide
    address public owner;                          // slot 0 — reserved
    uint256 public totalFunds;                     // slot 1 — reserved
    address public logic;                          // slot 2 — reserved
    mapping(address => uint256) public deposits;   // slot 3 — reserved

    // Registry-specific state — begins after all proxy-reserved slots
    bytes32 public registryName;   // slot 4
    address public registryOwner;  // slot 5

    event NameUpdated(bytes32 indexed newName);
    event OwnerUpdated(address indexed newOwner);

    // SAFE: writes to slot 4 — no proxy field lives there
    function setRegistryName(bytes32 newName) external {
        registryName = newName;
        emit NameUpdated(newName);
    }

    // SAFE: writes to slot 5 — no proxy field lives there
    function setRegistryOwner(address newOwner) external {
        registryOwner = newOwner;
        emit OwnerUpdated(newOwner);
    }
}

// Proxy vault — layout unchanged; logic contract is now aligned with it
contract VaultProxy_Safe {
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

    // SAFE: logic contract's layout is aligned — no slot collision possible
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
