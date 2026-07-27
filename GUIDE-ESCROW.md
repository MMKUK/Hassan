# Guide: Hassan Escrow

**One sentence:** Escrow locks HSN on-chain between a **buyer** and a **seller** until both agree — or the buyer reclaims after a timeout. No bank holds the money.

You need:

1. A running node (`GUIDE-NODE.md`)  
2. Two wallets (`GUIDE-WALLET.md`) — buyer + seller  
3. Buyer funded with enough HSN + fee  

---

## Picture (remember this)

```
1. AGREE   buyer + seller set amount + timeout
2. FUND    buyer publishes → HSN locks in a vault
3. SETTLE  both sign → pay seller
   or REFUND both sign → money back to buyer
   or TIMEOUT buyer alone reclaim after the clock
```

Watch live vaults: `http://127.0.0.1:8080/#/escrow`

---

## Words (simple)

| Word | Meaning |
|------|---------|
| Buyer | Pays / locks the HSN |
| Seller | Receives HSN if deal completes |
| Vault | On-chain lock (visible in Explorer) |
| Timeout | Blue-score deadline; then buyer can reclaim alone |
| Publish | Send a signed tx to the node (`fund` / `settle` / …) |

`open` only saves terms on **disk**.  
`fund` is what **locks money on the chain**.

---

## 0. Prepare two wallets

```bash
# Demo tip: use the SAME password so settle/refund can open both files
export HASSAN_WALLET_PASSWORD='shared-pass'
./target/release/hassan-wallet new buyer.json
./target/release/hassan-wallet new seller.json

./target/release/hassan-wallet address buyer.json
./target/release/hassan-wallet address seller.json
```

Fund the **buyer** address (mine on your node, or receive a send). Check:

```bash
./target/release/hassan-wallet balance hsn1BUYER…
```

If the node uses an API token:

```bash
export HASSAN_API_TOKEN='…'
```

---

## 1. Agree + open (buyer)

Amount is in **base units** (1 HSN = 100000000).  
Timeout is in **blue-score** steps (ask your operator what delay you want).

```bash
export HASSAN_WALLET_PASSWORD='shared-pass'
./target/release/hassan-wallet escrow open \
  hsn1SELLER… \
  100000000 \
  100000 \
  "goods" \
  buyer.json
```

You get an `escrow_id`. Terms are stored in `buyer.json.escrow.json`.

Interactive tutorial anytime:

```bash
./target/release/hassan-wallet escrow tutorial
```

---

## 2. Fund / publish (buyer) — locks HSN

```bash
export HASSAN_WALLET_PASSWORD='shared-pass'
./target/release/hassan-wallet escrow fund ESCROW_ID buyer.json
```

Check:

- Explorer → **Escrow** → vault shows **funded**  
- or: `hassan-wallet escrow vaults`

---

## 3a. Deal OK → pay seller (both wallets)

`settle` opens **both** JSON files. Today they must share the same
`HASSAN_WALLET_PASSWORD` (or both be plaintext `--insecure` keystores used only
for that co-sign step). Easiest clean demo: create buyer and seller with the
**same** password, or unlock both on one trusted machine.

```bash
export HASSAN_WALLET_PASSWORD='shared-for-cosign'
./target/release/hassan-wallet escrow settle ESCROW_ID \
  --with seller.json \
  buyer.json
```

---

## 3b. Deal cancelled → refund buyer (both wallets)

```bash
export HASSAN_WALLET_PASSWORD='shared-for-cosign'
./target/release/hassan-wallet escrow refund ESCROW_ID \
  --with seller.json \
  buyer.json
```

---

## 3c. Stuck past timeout → buyer reclaim alone

```bash
export HASSAN_WALLET_PASSWORD='shared-pass'
./target/release/hassan-wallet escrow timeout-claim ESCROW_ID buyer.json
```

Only works after the vault’s timeout blue-score is reached (Explorer shows **claimable**).

---

## 4. Status helpers

```bash
./target/release/hassan-wallet escrow status  ESCROW_ID buyer.json
./target/release/hassan-wallet escrow list    buyer.json
./target/release/hassan-wallet escrow history ESCROW_ID buyer.json
./target/release/hassan-wallet escrow vaults
```

---

## Rules (glass-clear)

- No admin can seize the vault  
- Seller cannot take the money alone  
- Buyer cannot release to seller alone (need both for settle)  
- After timeout, **buyer** can reclaim alone  
- Explorer is a mirror; the chain spend is final  

---

## Mini cheatsheet

| Step | Who | Command |
|------|-----|---------|
| Tutorial | anyone | `escrow tutorial` |
| Open terms | buyer | `escrow open SELLER AMT TIMEOUT buyer.json` |
| Lock money | buyer | `escrow fund ID buyer.json` |
| Pay seller | both | `escrow settle ID --with seller.json buyer.json` |
| Refund | both | `escrow refund ID --with seller.json buyer.json` |
| Timeout | buyer | `escrow timeout-claim ID buyer.json` |

More detail: `ESCROW.md` · `TUEP.md` · Explorer `#/escrow`
