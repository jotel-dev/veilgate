# VeilGate Privacy Model

## Summary

VeilGate is a privacy-first merchant checkout server for Zcash shielded payments running on testnet. The system is designed to minimize data exposure, avoid customer tracking, and eliminate custody risks by operating exclusively with an incoming viewing key.

The server never handles or stores a seed phrase, mnemonic, or spending key. It cannot spend funds. Payment addresses are derived deterministically per invoice from the incoming viewing key, allowing payments to be matched to invoices without customer memos. The checkout pages make no third-party requests, execute no tracking scripts, and serve all assets directly under a strict Content Security Policy (CSP). The server does not log client IP addresses, payment addresses, transaction IDs, or payment amounts.

## Who Sees What

The table below summarizes what data each participant or external observer can and cannot observe during a transaction:

| Observer / Participant | What They See | What They Do Not See |
| --- | --- | --- |
| Public Observers | Sees that a shielded transaction occurred, its block, time, size, fee, and the number of shielded actions. Funds moved in from a transparent address are visible at that step. | Cannot see sender, receiver, or amount of a payment from a shielded balance to a shielded address. |
| Merchant Server | Sees the amount and arrival time of each payment. Because it holds an incoming viewing key, it can decrypt every incoming payment to the account, though it only stores payments that match an invoice. | Cannot spend (the viewing key cannot spend). Does not see or handle seed phrases or spending keys. Does not log client IP addresses, invoice addresses, txids, or payment amounts. |
| lightwalletd Operator | Sees the scanner's IP address and which blocks it requests. | Does not see which payments are ours. |
| Hosting Provider | Sees HTTP connections to the site and holds the demo viewing key as a secret. | Cannot spend funds (the viewing key cannot spend). Does not see private keys or seed phrases. |
| Holder of the Invoice URL | The invoice page URL is a secret bearer token: anyone with it sees that invoice's status and amount. | Does not see other merchant invoices, customer identities, internal address indices, or server viewing keys. |
| Testnet Faucet Operator | Using a testnet faucet shows the invoice address to the faucet operator. | Does not see the checkout page, customer identity, or status on the VeilGate server unless given the invoice URL. |

## What VeilGate Does Not Protect

VeilGate provides shielded payment verification within explicit design boundaries. It does not provide total anonymity against all possible threat models:

1. **Transparent-to-Shielded Inflows**: Public observers cannot see sender, receiver, or amount of a payment from a shielded balance to a shielded address. However, funds moved in from a transparent address are visible on the public blockchain at that step. If a payer funds their shielded balance directly from a transparent address in an immediately linkable manner, that prior hop remains publicly visible.
2. **Bearer Token Invoice URLs**: The invoice page URL is a secret bearer token; anyone with it sees that invoice's status and amount. Anyone who obtains the public ID from browsing history, shoulder-surfing, or network interception can monitor the payment status and amount of that invoice.
3. **Third-Party Faucet Disclosure**: When testing with external services, using a testnet faucet shows the invoice address to the faucet operator. The faucet operator can correlate that address with the faucet requester's IP address.
4. **Merchant Viewing Scope**: The merchant server sees the amount and arrival time of each payment. Because it holds an incoming viewing key, it can decrypt every incoming payment to the account, though it only stores payments that match an invoice. A merchant or an operator with server access observes when payments arrive and their on-chain values.
5. **Network Metadata at lightwalletd**: The lightwalletd operator sees the scanner's IP address and which blocks it requests, not which payments are ours. If the merchant does not route lightwalletd traffic through Tor or a VPN, the gRPC node operator knows the server's network address.
6. **Hosting Infrastructure Access**: The hosting provider sees HTTP connections to the site and holds the demo viewing key as a secret. If the hosting infrastructure is compromised, attackers could read the incoming viewing key (enabling them to decrypt incoming transactions, but not spend funds) and inspect plaintext HTTP connections.
7. **Deep Block Reorganizations**: Reorganizations deeper than 20 blocks are outside the automated rollback window.
8. **Wallet Compatibility**: Customers need a wallet that supports the current network upgrade to construct compatible shielded transactions.

## Design Choices and Why

VeilGate's architecture is shaped by five core security and privacy decisions:

### 1. Viewing Key Not Spending Key
The server holds only an incoming viewing key; no seed or spending key is ever handled. The viewing key cannot spend.
- **Why**: Spending keys and mnemonic seeds are kept strictly offline on the merchant's secure wallet. Even if the web server, database, or container environment is fully compromised, an attacker cannot steal or transfer merchant funds.

### 2. One Address per Invoice
Invoice addresses are derived per invoice index from that incoming viewing key and mapped back to the invoice without memos.
- **Why**: Address reuse correlates distinct transactions and allows third parties to trace invoice volumes. By generating a fresh, diversifier-derived address for each invoice, customer payments remain cryptographically isolated.

### 3. No Memos
We do not request memos. Payment detection is performed strictly by scanning for notes addressed to the invoice's derived address. VeilGate's scanner reads compact blocks, which carry no memos, so it neither reads nor stores them; a holder of the viewing key could read memos by downloading full transactions.
- **Why**: Requiring customers to paste invoice IDs or transaction references into payment memos causes failed payments when memos are mistyped or omitted. Additionally, memos create avoidable metadata trails. Eliminating memos makes payment straightforward while keeping transactions metadata-free.

### 4. No Third-Party Calls
No third-party requests from the checkout pages; strict CSP; no request logging; no IPs, addresses, txids or amounts logged; rate-limit keys are salted hashes of the client identity.
- **Why**: Remote CDN scripts, web fonts, analytics, and tracking pixels leak customer IP addresses, browser fingerprints, and visit times to external companies. VeilGate uses local inline SVGs, standard system font stacks, and local assets, enforced by a zero-external-origin Content Security Policy.

### 5. Random Public IDs
Public invoice references use random 128-bit hexadecimal strings (`public_id`), while internal diversifier indices (`address_index`) remain private.
- **Why**: Sequential IDs or index numbers would allow observers to infer total sales volume and invoice velocity. High-entropy random IDs ensure invoice URLs cannot be guessed or enumerated.

## Verification

The privacy and payment mechanisms have been verified through automated testing and live on-chain operations:

- **Automated Tests**: 95 automated tests pass (`cargo test`), including injection, CSRF, header, rate-limit, and no-leak tests.
- **Local Test (18 Oct 2026)**: A 0.1 ZEC testnet invoice was paid by a 0.125 TAZ faucet payment and showed Paid with 0.125 received. As a fact about the local test only, database records showed payments per pool column as: orchard: 0, ironwood: 1.
- **Hosted Test (21 Oct 2026)**: On https://veilgate-demo.onrender.com, a 1.0 ZEC invoice paid by a 1 TAZ faucet payment went from Awaiting payment to Paid about two minutes after the faucet sent the payment, with confirmations set to 1 (observed wall-clock time; it depends on network block time and the scanner's 30-second polling interval).
- **Faucet Receipt Memo Observation**: Fauzec's page states its payments carry a default receipt memo; as an observation about the faucet used in testing, VeilGate does not read it.
- **Operational Hygiene**: No request logging; no IPs, addresses, txids or amounts logged; rate-limit keys are salted hashes of the client identity.

## Limitations

The current release has the following known limits:

- **Testnet Only**: Designed and configured exclusively for Zcash testnet.
- **Single Merchant**: Designed for single-merchant deployments; multiple merchants are not supported.
- **Catch-up Chunk Size**: The block scanner catches up in 500-block chunks.
- **Ephemeral Free-Tier Hosting**: The free Render instance sleeps after about 15 minutes and wakes in about 50 seconds; its disk is not persistent so invoices can reset.
- **Client Upgrade Requirements**: Customers need a wallet that supports the current network upgrade.
- **Third-Party Faucet Links**: The demo and pay pages contain plain links to two third-party testnet faucets; following them leaves VeilGate and the faucet operator sees any address pasted there.
- **Hosting Platform Logs**: The hosting platform may keep its own request logs; the VeilGate application itself does not log requests.
- **Testnet Explorers and Demonstration**: The public testnet explorers we tried did not display our test transactions (we did not determine why), so no explorer screenshot of our own transaction is included; the demo video uses a mainnet fully shielded transaction purely as a labelled illustration of what an observer sees.
- **Untested Functionality**:
  - Paying from a real wallet app by scanning the QR or opening the link.
  - Mainnet.
  - Reorgs deeper than 20 blocks.
  - Mempool (0-confirmation) detection.
  - Multiple merchants.

