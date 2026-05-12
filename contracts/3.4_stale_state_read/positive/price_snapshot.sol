// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.4
// @vulnerable: true
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(snapshotPrice stored at position open) → WRITE(borrow) without
//               refreshing the snapshot against the current oracle price
// @description: A collateralised credit line stores the ETH/USD price at open time
//               as snapshotPrice and uses it for all subsequent collateral valuations.
//               The snapshot is never refreshed. An attacker opens a credit line when
//               the ETH price is high (favourable snapshot), waits for the price to
//               drop, then draws down the full credit limit — which is still computed
//               against the stale high snapshot. The actual collateral value no longer
//               supports the loan, leaving the protocol undercollateralised.
// @patching_strategy: Re-read the current oracle price inside borrow() rather than
//                     relying on the stored snapshot — see negative/price_snapshot.sol

interface IPriceFeed {
    function getPrice() external view returns (uint256 priceUsd, uint256 updatedAt);
}

contract CreditLineVault_Vulnerable {
    address public owner;
    IPriceFeed public priceFeed;

    struct CreditLine {
        uint256 collateralEth;  // ETH deposited as collateral
        uint256 snapshotPrice;  // ETH/USD price recorded at open — never refreshed
        uint256 debt;           // USD borrowed so far (18 dec)
        uint256 openedAt;
    }

    mapping(address => CreditLine) public lines;

    uint256 public constant COLLATERAL_RATIO = 150; // 150 % over-collateralisation

    event LineOpened(address indexed user, uint256 ethAmount, uint256 price);
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

        (uint256 price,) = priceFeed.getPrice();
        require(price > 0, "bad price");

        lines[msg.sender] = CreditLine({
            collateralEth: msg.value,
            snapshotPrice: price,   // price locked in at open time
            debt:          0,
            openedAt:      block.timestamp
        });

        emit LineOpened(msg.sender, msg.value, price);
    }

    function borrow(uint256 usdAmount) external {
        CreditLine storage line = lines[msg.sender];
        require(line.collateralEth > 0, "no open line");

        // VULNERABLE: uses snapshotPrice (set at open, never updated)
        // If ETH price has fallen since open, this overestimates collateral value
        uint256 collateralUsd = (line.collateralEth * line.snapshotPrice) / 1e18;
        uint256 maxBorrow     = (collateralUsd * 100) / COLLATERAL_RATIO;

        require(line.debt + usdAmount <= maxBorrow, "undercollateralised");
        line.debt += usdAmount;

        emit Borrowed(msg.sender, usdAmount, line.snapshotPrice);
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
