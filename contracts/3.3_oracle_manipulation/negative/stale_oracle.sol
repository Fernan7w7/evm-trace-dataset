// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.3
// @vulnerable: false
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(price feed) → WRITE(borrow) with no staleness check — resolved
// @description: Patched version reads the updatedAt field from latestRoundData()
//               and requires the price to be no older than MAX_STALENESS seconds.
//               If the oracle feed goes stale, all borrows revert until the feed
//               resumes — preventing exploitation of a lagged price.
// @patching_strategy: Added require(block.timestamp - updatedAt <= MAX_STALENESS)
//                     inside getEthPriceUsd() before returning the price

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

contract PriceFeedVault_Safe {
    address public owner;
    IAggregatorV3Interface public priceFeed;

    mapping(address => uint256) public collateralEth;
    mapping(address => uint256) public debtUsd;

    uint256 public constant COLLATERAL_RATIO = 150;
    uint256 public constant MAX_STALENESS    = 3600; // 1 hour

    event CollateralDeposited(address indexed user, uint256 ethAmount);
    event Borrowed(address indexed user, uint256 usdAmount);
    event Repaid(address indexed user, uint256 usdAmount);

    constructor(address _feed) {
        owner     = msg.sender;
        priceFeed = IAggregatorV3Interface(_feed);
    }

    // SAFE: reverts if the price was last updated more than MAX_STALENESS seconds ago
    function getEthPriceUsd() public view returns (uint256) {
        (, int256 answer,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(answer > 0, "invalid price");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale price feed");
        return uint256(answer) * 1e10;
    }

    function depositCollateral() external payable {
        require(msg.value > 0, "zero deposit");
        collateralEth[msg.sender] += msg.value;
        emit CollateralDeposited(msg.sender, msg.value);
    }

    function borrow(uint256 usdAmount) external {
        uint256 priceUsd      = getEthPriceUsd(); // reverts on stale feed
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
