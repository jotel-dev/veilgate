# VeilGate project brief (read this first for every task)

## What we are building
VeilGate is a privacy-first merchant checkout for Zcash shielded payments. A merchant creates an invoice, VeilGate derives a fresh shielded address for it, and the customer pays by opening a ZIP 321 link or scanning a QR code with a Zcash wallet. A server holding only an incoming viewing key detects the payment and marks the invoice paid after confirmations. It is a solo hackathon entry for Zecathon 2026 (Shielded Payments track), due Oct 28 2026, 23:59 UTC. Judges score Privacy (leaks disqualify), Usefulness, Execution (working beats ambitious) and Originality. The repo is open source. We run on TESTNET only.

## What already exists (Rust, in backend/)
addresses.rs (viewing key loading, one Orchard-receiver address per invoice index), invoices.rs (SQLite store, invoices, payments, payment states), scanner.rs and bin/scanner.rs (scans Orchard and Ironwood compact blocks from lightwalletd with the incoming viewing key only, retry and backoff, reorg rollback), bin/keygen.rs (merchant key tool), bin/invoice_demo.rs. 34 tests pass. Detection of a real on-chain payment is still untested.

## Hard rules
- Only the incoming viewing key is ever handled. Never a seed, mnemonic or spending key. Never run keygen.
- Never log addresses, txids, amounts, IPs or keys. Public invoice ids in URLs are secret bearer tokens.
- No third-party requests of any kind: no CDN, web fonts, analytics or remote images.
- Never expose the internal address index publicly.
- No emojis anywhere: not in the UI, code, docs, comments or commit messages. Icons are inline SVG.

## Honest claims only
Never invent statistics, user or merchant counts, uptime figures, testimonials, pricing, accounts or sign-up, an API, or "instant" settlement. Never mention other chains or currencies (no Solana, no USDC). Never say "anonymous" or "untraceable". True statements we may make:
- Public observers cannot see the sender, receiver or amount of a payment made from a shielded balance to a shielded address. Funds moved in from a transparent address are visible at that step.
- The merchant server sees the amount and arrival time of each payment, and any memo the customer's wallet includes (we do not request one).
- The lightwalletd operator sees the scanner's IP address and which blocks it requests, but not which payments are ours.
- The server holds an incoming viewing key: it can detect payments but cannot spend them.
- Each invoice has its own address, so payments are matched without memos.
- Customers need an up-to-date wallet (NU6.3 and Ironwood aware).
Known limits: testnet only, reorgs handled to about 20 blocks, no mempool detection, single merchant.

## Design
Reference mockup: docs/design/landing-reference.png. Use its layout and visual style (clean, rounded cards, green-to-teal accents, light and dark themes, monospace eyebrow labels). Do NOT copy its text: it contains fake claims. Logos: docs/design/logo-dark-source.png (for dark theme) and logo-light-source.png (for light theme). Icons: Lucide-style inline SVG (ISC license). System font stack, no web fonts.

## Process
Show full unedited cargo build and cargo test output. State plainly what is untested. Keep all existing tests passing.
