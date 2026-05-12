// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.4
// @vulnerable: false
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(snapshotPrice) → WRITE(borrow) without refreshing snapshot — resolved
// @description: Patched version discards snapshotPrice for collateral valuation.
//               borrow() re-reads the current oracle price and requires it to be
//               fresh (within MAX_PRICE_AGE). The credit limit always reflects
//               the current collateral value, so a price drop since open is
//               immediately reflected in the available borrow capacity.
// @patching_strategy: Replaced line.snapshotPrice with a live priceFeed.getPrice()
//                     call inside borrow(); added a staleness check on updatedAt

interface IPriceFeed {
    function getPrice() external view returns (uint256 priceUsd, uint256 updatedAt);
}

contract CreditLineVault_Safe {
    address public owner;
    IPriceFeed public priceFeed;

    struct CreditLine {
        uint256 collateralEth;
        uint256 debt;
        uint256 openedAt;
        // snapshotPrice removed — no longer used for collateral valuation
    }

    mapping(address => CreditLine) public lines;

    uint256 public constant COLLATERAL_RATIO = 150;
    uint256 public constant MAX_PRICE_AGE    = 3600; // 1 hour

    event LineOpened(address indexed user, uint256 ethAmount);
    event Borrowed(address indexed user, uint256 usdAmount, uint256 priceUsed);
    event Repaid(address indexed user, uint256 usdAmount);
    event LineClosed(address indexed user);

    constructor(address _feed) {
        owner     = msg.sender;
        priceFeed = IPriceFeed(_feed);
    }

    function openLine() external payable {
        require(msg.value > 0, "no collateral");
        require(lines[msg.sender].collateralEth == 0, "line already open");

        lines[msg.sender] = CreditLine({
            collateralEth: msg.value,
            debt:          0,
            openedAt:      block.timestamp
        });

        emit LineOpened(msg.sender, msg.value);
    }

    function borrow(uint256 usdAmount) external {
        CreditLine storage line = lines[msg.sender];
        require(line.collateralEth > 0, "no open line");

        // SAFE: re-reads current price on every borrow — snapshot never used for valuation
        (uint256 currentPrice, uint256 updatedAt) = priceFeed.getPrice();
        require(currentPrice > 0, "bad price");
        require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "price too stale");

        uint256 collateralUsd = (line.collateralEth * currentPrice) / 1e18;
        uint256 maxBorrow     = (collateralUsd * 100) / COLLATERAL_RATIO;

        require(line.debt + usdAmount <= maxBorrow, "undercollateralised");
        line.debt += usdAmount;

        emit Borrowed(msg.sender, usdAmount, currentPrice);
    }

    function repay(uint256 usdAmount) external {
        CreditLine storage line = lines[msg.sender];
        require(line.debt >= usdAmount, "overpayment");
        line.debt -= usdAmount;
        emit Repaid(msg.sender, usdAmount);
    }

    function closeLine() external {
        CreditLine storage line = lines[msg.sender];
        require(line.debt == 0, "repay debt first");
        uint256 eth = line.collateralEth;
        delete lines[msg.sender];
        (bool ok,) = msg.sender.call{value: eth}("");
        require(ok, "eth return failed");
        emit LineClosed(msg.sender);
    }
}
