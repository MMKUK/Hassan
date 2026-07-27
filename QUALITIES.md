# Hassan — Qualities

Factual capabilities of this codebase (genesis `hassan-genesis-v31`).

## Cryptography
- ML-DSA-87 (FIPS 204) signatures on blocks and spends  
- Blake3-512 hashing (PoW, digests, commitments)  
- Optional SLH-DSA dual-signature on custody certificates  
- Absolute Binding Signatures (number + scheme type 87) via `hassan-signer`

## Consensus & money
- GHOSTDAG BlockDAG (`k=40`), ~100 ms target block time  
- Blue-work weighted DAA (window 661)  
- Economic finality ~12 hours (432000 blues); pruning depth 864000  
- Supply cap 25,000,000 HSN; subsidy 50 HSN; halving every 250,000 blue-score  
- PoW bootstrap floor 7000 until 1M HSN minted, then hard floor `2^24`

## Settlement & products
- UTXO peer transfers; fee market with RBF and confirmation-target estimates  
- BDPE peer escrow: 2-of-2 settle/refund or buyer timeout reclaim  
- On-chain title registry with hardened escrow rules  
- Embedded glass explorer (blocks, watch wallet, escrow guide)

## Operations & security posture
- Node roles: archive / validator / light  
- Public lock: required API token; refuses unauth writes, relax-net, bootstrap-easy  
- API defaults to loopback; P2P caps, bans, peer pins, Tor outbound dials  
- Fail-closed chainstate load; wire protocol 7  

Honest limits: see [`SECURITY.md`](SECURITY.md). Guides: [`GUIDE-NODE.md`](GUIDE-NODE.md) · [`GUIDE-WALLET.md`](GUIDE-WALLET.md) · [`GUIDE-SIGNER.md`](GUIDE-SIGNER.md) · [`GUIDE-ESCROW.md`](GUIDE-ESCROW.md).
