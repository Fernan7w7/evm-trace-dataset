// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.3
// @vulnerable: false
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(spot price from reserves) → WRITE(borrow) with no TWAP guard — resolved
// @description: Patched version replaces the spot price read with a time-weighted
//               average price (TWAP) computed over a configurable window. Because
//               the TWAP accumulates price observations across multiple blocks, a
//               flash-loan manipulation in a single block produces only a tiny
//               change in the TWAP — not enough to make a borrow profitable.
// @patching_strategy: Replaced getReserves() spot price with a keeper-updated TWAP
//                     using Uniswap V2's price0CumulativeLast accumulator;
//                     borrow() reverts if the TWAP has not been refreshed recently

interface IUniswapV2Pair {
    function getReserves() external view returns (
        uint112 reserve0,
        uint112 reserve1,
        uint32  blockTimestampLast
    );
    function price0CumulativeLast() external view returns (uint256);
}

contract LendingPool_Safe {
    address public owner;
    IUniswapV2Pair public pair;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    uint256 public constant COLLATERAL_RATIO = 150;
    uint32  public constant TWAP_WINDOW      = 30 minutes;
    uint32  public constant MAX_TWAP_AGE     = 60 minutes; // borrow reverts if TWAP is older than this

    // TWAP state — updated by a keeper calling updateTWAP()
    uint256 public twapPrice;           // UQ112x112 average, scaled to 1e18 for use
    uint256 public twapUpdatedAt;
    uint256 private cumulativeSnapshot;
    uint32  private timestampSnapshot;

    event CollateralDeposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 ethAmount);
    event Repaid(address indexed user, uint256 ethAmount);
    event TWAPUpdated(uint256 price, uint256 timestamp);

    constructor(address _pair) {
        owner = msg.sender;
        pair  = IUniswapV2Pair(_pair);
        // seed the snapshot so the first updateTWAP() call has a baseline
        (,, uint32 ts) = pair.getReserves();
        cumulativeSnapshot = pair.price0CumulativeLast();
        timestampSnapshot  = ts;
    }

    // SAFE: called by a keeper between blocks — builds a time-weighted average
    // A flash loan can only affect a single block's contribution to the accumulator
    function updateTWAP() external {
        (,, uint32 currentTs) = pair.getReserves();
        uint256 currentCumulative = pair.price0CumulativeLast();
        uint32  elapsed = currentTs - timestampSnapshot;

        require(elapsed >= TWAP_WINDOW, "window not elapsed");

        // Average price over the elapsed window (UQ112x112 → scale to 1e18)
        uint256 avgQ112 = (currentCumulative - cumulativeSnapshot) / elapsed;
        twapPrice       = (avgQ112 * 1e18) >> 112;
        twapUpdatedAt   = block.timestamp;

        cumulativeSnapshot = currentCumulative;
        timestampSnapshot  = currentTs;

        emit TWAPUpdated(twapPrice, block.timestamp);
    }

    function depositCollateral(uint256 tokenAmount) external {
        collateral[msg.sender] += tokenAmount;
        emit CollateralDeposited(msg.sender, tokenAmount);
    }

    function borrow(uint256 ethAmount) external {
        // SAFE: reverts if TWAP hasn't been refreshed recently — stale price blocked
        require(block.timestamp - twapUpdatedAt <= MAX_TWAP_AGE, "twap too stale");
        require(twapPrice > 0, "twap not initialized");

        uint256 collateralEth = (collateral[msg.sender] * twapPrice) / 1e18;
        uint256 maxBorrow     = (collateralEth * 100) / COLLATERAL_RATIO;

        require(debt[msg.sender] + ethAmount <= maxBorrow, "undercollateralized");
        debt[msg.sender] += ethAmount;

        (bool ok,) = msg.sender.call{value: ethAmount}("");
        require(ok, "eth transfer failed");
        emit Borrowed(msg.sender, ethAmount);
    }

    function repay() external payable {
        require(debt[msg.sender] >= msg.value, "overpayment");
        debt[msg.sender] -= msg.value;
        emit Repaid(msg.sender, msg.value);
    }

    receive() external payable {}
}
