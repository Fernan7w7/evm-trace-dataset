// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.3
// @vulnerable: true
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(price feed) → WRITE(borrow) with no staleness check on updatedAt
// @description: The vault reads price from a Chainlink-style feed but never inspects
//               the updatedAt timestamp returned alongside the price. If the oracle
//               stops updating (network outage, sequencer downtime, deprecated feed),
//               the contract keeps using the last known price indefinitely. An
//               attacker monitors oracle health, waits for the feed to go stale,
//               then exploits the price discrepancy between the stale feed price
//               and the true market price to borrow under- or over-collateralized.
// @patching_strategy: Add require(block.timestamp - updatedAt <= MAX_STALENESS)
//                     before using the price — see negative/stale_oracle.sol

interface IAggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80  roundId,
        int256  answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80  answeredInRound
    );
    function decimals() external view returns (uint8);
}

contract PriceFeedVault_Vulnerable {
    address public owner;
    IAggregatorV3Interface public priceFeed;

    mapping(address => uint256) public collateralEth; // ETH deposited
    mapping(address => uint256) public debtUsd;       // USD borrowed (18 dec)

    uint256 public constant COLLATERAL_RATIO = 150;

    event CollateralDeposited(address indexed user, uint256 ethAmount);
    event Borrowed(address indexed user, uint256 usdAmount);
    event Repaid(address indexed user, uint256 usdAmount);

    constructor(address _feed) {
        owner     = msg.sender;
        priceFeed = IAggregatorV3Interface(_feed);
    }

    // VULNERABLE: updatedAt is returned but never checked — stale price accepted silently
    function getEthPriceUsd() public view returns (uint256) {
        (, int256 answer,,,) = priceFeed.latestRoundData();
        require(answer > 0, "invalid price");
        // normalise to 18 decimals (Chainlink ETH/USD has 8 decimals)
        return uint256(answer) * 1e10;
    }

    function depositCollateral() external payable {
        require(msg.value > 0, "zero deposit");
        collateralEth[msg.sender] += msg.value;
        emit CollateralDeposited(msg.sender, msg.value);
    }

    function borrow(uint256 usdAmount) external {
        // VULNERABLE: uses stale price if oracle hasn't updated recently
        uint256 priceUsd      = getEthPriceUsd();
        uint256 collateralUsd = (collateralEth[msg.sender] * priceUsd) / 1e18;
        uint256 maxBorrow     = (collateralUsd * 100) / COLLATERAL_RATIO;

        require(debtUsd[msg.sender] + usdAmount <= maxBorrow, "undercollateralized");
        debtUsd[msg.sender] += usdAmount;
        emit Borrowed(msg.sender, usdAmount);
    }

    function repay(uint256 usdAmount) external {
        require(debtUsd[msg.sender] >= usdAmount, "overpayment");
        debtUsd[msg.sender] -= usdAmount;
        emit Repaid(msg.sender, usdAmount);
    }
}
