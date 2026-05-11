# Justification — 1.1 Reentrancy (Value Transfer)
**Source:** SmartBugs Curated  
**Precondition:** `CALL → WRITE` where the CALL transfers ETH value before the balance state variable is updated.

All 30 contracts below exhibit the classic CEI (Checks-Effects-Interactions) violation: ETH is sent to an external address via `.call.value(...)()` or `.transfer()` **before** the sender's balance mapping is decremented. A malicious fallback function can re-enter the withdrawal function and drain the contract before the balance write occurs.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol` | `PERSONAL_BANK.Collect` | `msg.sender.call.value(_am)()` → `balances[msg.sender]-=_am` |
| `0x23a91059fdc9579a9fbd0edc5f2ea0bfdb70deb4.sol` | `PrivateBank.CashOut` | `msg.sender.call.value(_am)()` → balance decrement |
| `0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol` | `ACCURAL_DEPOSIT.Collect` | `msg.sender.call.value(_am)()` → balance decrement |
| `0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol` | `PRIVATE_ETH_CELL.Collect` | `msg.sender.call.value(_am)()` → balance decrement |
| `0x561eac93c92360949ab1f1403323e6db345cbf31.sol` | `BANK_SAFE.Collect` | `msg.sender.call.value(_am)()` → balance decrement |
| `0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol` | `TokenBank.WithdrawToHolder` | `_addr.call.value(_wei)()` → `Holders[_addr]-=_wei` |
| `0x7541b76cb60f4c60af330c208b0623b7f54bf615.sol` | `U_BANK.Collect` | `msg.sender.call.value(_am)()` → `acc.balance-=_am` |
| `0x7a8721a9d64c74da899424c1b52acbf58ddc9782.sol` | `PrivateDeposit.CashOut` | `msg.sender.call.value(_am)()` → balance decrement |
| `0x7b368c4e805c3870b6c49a3f1f49f69af8662cf3.sol` | `W_WALLET.Collect` | `msg.sender.call.value(_am)()` → `acc.balance-=_am` |
| `0x8c7777c45481dba411450c228cb692ac3d550344.sol` | `ETH_VAULT.CashOut` | `msg.sender.call.value(_am)()` → balance decrement |
| `0x93c32845fae42c83a70e5f06214c8433665c2ab5.sol` | `X_WALLET.Collect` | `msg.sender.call.value(_am)()` → `acc.balance-=_am` |
| `0x941d225236464a25eb18076df7da6a91d0f95e9e.sol` | `ETH_FUND.CashOut` | `msg.sender.call.value(_am)()` → balance decrement |
| `0x96edbe868531bd23a6c05e9d0c424ea64fb1b78b.sol` | `PENNY_BY_PENNY.Collect` | `msg.sender.call.value(_am)()` → `acc.balance-=_am` |
| `0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8.sol` | `DEP_BANK.Collect` | `msg.sender.call.value(_am)()` → balance decrement |
| `0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol` | `Private_Bank.CashOut` | `msg.sender.call.value(_am)()` → balance decrement |
| `0xb93430ce38ac4a6bb47fb1fc085ea669353fd89e.sol` | `PrivateBank.CashOut` | `msg.sender.call.value(_am)()` → balance decrement |
| `0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | `ETH_VAULT.CashOut` | `msg.sender.call.value(_am)()` → balance decrement |
| `0xbe4041d55db380c5ae9d4a9b9703f1ed4e7e3888.sol` | `MONEY_BOX.Collect` | `msg.sender.call.value(_am)()` → `acc.balance-=_am` |
| `0xcead721ef5b11f1a7b530171aab69b16c5e66b6e.sol` | `WALLET.Collect` | `msg.sender.call.value(_am)()` → `acc.balance-=_am` |
| `0xf015c35649c82f5467c9c74b7f28ee67665aad68.sol` | `MY_BANK.Collect` | `msg.sender.call.value(_am)()` → `acc.balance-=_am` |
| `etherbank.sol` | `EtherBank.withdrawBalance` | `msg.sender.call.value(amountToWithdraw)()` → `userBalances[msg.sender] = 0` |
| `etherstore.sol` | `EtherStore.withdrawFunds` | `msg.sender.call.value(_weiToWithdraw)()` → balance and timestamp update |
| `reentrance.sol` | `Reentrance.withdraw` | `msg.sender.call.value(_amount)()` → `balances[msg.sender] -= _amount` |
| `reentrancy_bonus.sol` | `withdrawReward` | `recipient.call.value(amountToWithdraw)("")` → `claimedBonus[recipient] = true` |
| `reentrancy_cross_function.sol` | `withdrawBalance` | `msg.sender.call.value(amountToWithdraw)("")` → `userBalances[msg.sender] = 0` |
| `reentrancy_dao.sol` | `ReentrancyDAO.withdrawAll` | `msg.sender.call.value(oCredit)()` → `credit[msg.sender] = 0` |
| `reentrancy_insecure.sol` | `withdrawBalance` | `msg.sender.call.value(amountToWithdraw)("")` → `userBalances[msg.sender] = 0` |
| `reentrancy_simple.sol` | `withdrawBalance` | `msg.sender.call.value(userBalance[msg.sender])()` → balance zeroed |
| `simple_dao.sol` | `SimpleDAO.withdraw` | `msg.sender.call.value(amount)()` → `credit[msg.sender] -= amount` |
| `spank_chain_payment.sol` | `LCOpenTimeout` | `.transfer()` sends ETH → `delete Channels[_lcID]` |

**Why NOT 1.2:** All contracts transfer ETH via the vulnerable CALL. The TRANSFER op type is present in the trace, distinguishing them from state-only reentrancy.
