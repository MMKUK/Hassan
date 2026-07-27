# Guide: Hassan Wallet

**One sentence:** The wallet holds your keys, shows balances, and sends HSN. It talks to a **running node**.

Start the node first (see `GUIDE-NODE.md`).

---

## 1. Build once

```bash
cargo build --release --bin hassan-wallet
```

Binary: `./target/release/hassan-wallet`

---

## 2. Create a wallet (password required)

```bash
export HASSAN_WALLET_PASSWORD='choose-a-strong-password'
./target/release/hassan-wallet new my.json
```

- Creates encrypted `my.json` (Argon2id + ChaCha20-Poly1305)
- Prints your address: `hsn1…`
- **Never share** the file or the password

Show address again:

```bash
HASSAN_WALLET_PASSWORD='…' ./target/release/hassan-wallet address my.json
```

---

## 3. Point at your node

Default API: `http://127.0.0.1:8080`

If the node printed an API token, export it for send / mine / escrow publish:

```bash
export HASSAN_API_TOKEN='token-from-node-terminal'
```

Check you are on the same chain:

```bash
./target/release/hassan-wallet network
```

---

## 4. Balance and coins

```bash
# Balance (use your hsn1 address)
./target/release/hassan-wallet balance hsn1…

# List UTXOs locked to an address
./target/release/hassan-wallet utxos hsn1…
```

Amounts are in **base units** (like sats). 1 HSN = 100_000_000 base units.

---

## 5. Send HSN

```bash
# Min fee
HASSAN_WALLET_PASSWORD='…' \
  ./target/release/hassan-wallet send hsn1RECEIVER AMOUNT my.json

# Choose fee
HASSAN_WALLET_PASSWORD='…' \
  ./target/release/hassan-wallet send-fee hsn1RECEIVER AMOUNT FEE my.json

# Fee hints from the node
./target/release/hassan-wallet fee-estimate
```

Stuck in mempool? Bump fee with the **same nonce**:

```bash
HASSAN_WALLET_PASSWORD='…' \
  ./target/release/hassan-wallet bump hsn1RECEIVER AMOUNT NONCE NEW_FEE my.json
```

---

## 6. Watch in the explorer (no keys)

Browser: `http://127.0.0.1:8080/#/wallet`

Paste an `hsn1…` address — **read-only** watch card (like a BlueWallet watch view). Signing stays in `hassan-wallet`.

---

## 7. Mini cheatsheet

| Want | Command |
|------|---------|
| New wallet | `hassan-wallet new my.json` |
| Address | `hassan-wallet address my.json` |
| Chain info | `hassan-wallet network` |
| Balance | `hassan-wallet balance hsn1…` |
| Send | `hassan-wallet send hsn1… AMOUNT my.json` |
| Fees | `hassan-wallet fee-estimate` |
| Escrow | see `GUIDE-ESCROW.md` |

Always pass `HASSAN_WALLET_PASSWORD` for commands that open `my.json`.

---

## Picture

```
[ my.json + password ]  --sign-->  [ hassan-wallet ]  --HTTP-->  [ hassan node :8080 ]
                                      |
                                      v
                              Explorer #/wallet (watch only)
```

Safety:

- Password protects the file at rest  
- Node API token protects **writes** on the node  
- Never paste your keystore into a website  

Next: peer trade flow → `GUIDE-ESCROW.md`
