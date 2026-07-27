# Guide: Hassan Signer

**One sentence:** Offline ML-DSA-87 keys — create, sign, verify. Does **not** talk to a node.

Same keystore format as `hassan-wallet` (`HASSAN_WALLET_PASSWORD`).

```bash
cargo build --release --bin hassan-signer

export HASSAN_WALLET_PASSWORD='secret'
./target/release/hassan-signer new keys.json
./target/release/hassan-signer address keys.json
./target/release/hassan-signer pubkey keys.json

./target/release/hassan-signer sign hassan-doc "hello world" keys.json > sig.json
./target/release/hassan-signer verify hassan-doc "hello world" sig.json
```

Raw bytes: `hassan-signer sign-hex <DOMAIN> <HEX> [FILE]`

Help: `./target/release/hassan-signer --help`
