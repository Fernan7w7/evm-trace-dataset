// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @taxonomy_id: 3.3
// @vulnerable: true
// @trace_status: future_work
// @requires: READ operation emission in behavior extractor
// @precondition: READ(spot price from reserves) → WRITE(borrow) with no TWAP guard
// @description: The lending pool reads the token/ETH price directly from a Uniswap
//               V2 pair's current reserves. An attacker can flash-loan a large ETH
//               amount, swap it into the pair to inflate the token's apparent price,
//               then call depositCollateral() and borrow() in the same transaction —
//               the inflated spot price makes their collateral look more valuable
//               than it is. After borrowing the excess, the attacker repays the
//               flash loan. The entire exploit completes atomically.
// @patching_strategy: Replace getReserves() spot price with a TWAP computed over
//                     multiple blocks — see negative/spot_price_oracle.sol

interface IUniswapV2Pair {
    function getReserves() external view returns (
        uint112 reserve0,
        uint112 reserve1,
        uint32  blockTimestampLast
    );
    function price0CumulativeLast() external view returns (uint256);
}

contract LendingPool_Vulnerable {
    address public owner;
    IUniswapV2Pair public pair; // token (reserve0) / ETH (reserve1)

    mapping(address => uint256) public collateral; // token amount deposited
    mapping(address => uint256) public debt;       // ETH borrowed

    uint256 public constant COLLATERAL_RATIO = 150; // 150 % — borrow up to 2/3 of collateral value

    event CollateralDeposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 ethAmount);
    event Repaid(address indexed user, uint256 ethAmount);

    constructor(address _pair) {
        owner = msg.sender;
        pair  = IUniswapV2Pair(_pair);
    }

    // VULNERABLE: reads current reserves — manipulable via flash loan in the same tx
    function getTokenPriceInEth() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        require(reserve0 > 0, "empty pool");
        // price = ETH per token (reserve1 / reserve0), scaled to 1e18
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function depositCollateral(uint256 tokenAmount) external {
        collateral[msg.sender] += tokenAmount;
        emit CollateralDeposited(msg.sender, tokenAmount);
    }

    function borrow(uint256 ethAmount) external {
        // VULNERABLE: spot price used here — inflated by a flash loan moments earlier
        uint256 price          = getTokenPriceInEth();
        uint256 collateralEth  = (collateral[msg.sender] * price) / 1e18;
        uint256 maxBorrow      = (collateralEth * 100) / COLLATERAL_RATIO;

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
