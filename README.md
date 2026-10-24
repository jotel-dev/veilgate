# VeilGate

**Network: Zcash testnet. No real funds are involved. A hosted demo is live.**

Privacy-first shielded payment checkout for merchants. Built for Zecathon 2026 (Shielded Payments track). Testnet only.

Demo video: (link added at submission)

## Who It Is For

VeilGate is for a small shop or freelancer that wants to receive shielded payments with a server that holds only a watch-only key. The server can detect payments but cannot spend them.

Live demo: https://veilgate-demo.onrender.com

The hosted merchant dashboard is private and is demonstrated in the submission video. The instructions below allow anyone to run their own local instance and merchant dashboard.

## Try It in Three Steps

1. Open the demo checkout page at https://veilgate-demo.onrender.com/demo
2. Create an invoice (the default is 0.01 test coin).
3. Copy the derived payment address, paste it into a testnet faucet such as [faucet.testnet.valargroup.dev](https://faucet.testnet.valargroup.dev) or [fauzec.com](https://fauzec.com), and watch the invoice turn Paid.
4. Faucets can be paused or rate limited; if none works, open the "See a real completed payment" card on /demo to see a real testnet payment detected by the live server.

## How It Works

VeilGate allows merchants to accept shielded payments without handling private keys or requiring customer memos:

1. A merchant creates an invoice with a requested amount and expiration window.
2. VeilGate deterministically derives a fresh, unique shielded payment address for that invoice index from an incoming viewing key.
3. The customer opens a ZIP 321 payment URI or scans a QR code with a compatible Zcash wallet.
4. A background scanner holding only the incoming viewing key inspects compact blocks from lightwalletd, decrypts matching notes, maps the payment back to the invoice by address without requiring payment memos, and marks the invoice Paid after required block confirmations.

For full architectural details, see the [Privacy Model](docs/privacy-model.md).

## What Is Tested and What Is Untested

### Verified (Tested)

- **Local test (18 Oct 2026)**: A 0.1 ZEC testnet invoice was paid by a 0.125 TAZ faucet payment and showed Paid with 0.125 received. As a fact about the local test only, database records showed payments per pool column as: orchard: 0, ironwood: 1.
- **Hosted test (21 Oct 2026)**: On https://veilgate-demo.onrender.com a 1.0 ZEC invoice paid by a 1 TAZ faucet payment went from Awaiting payment to Paid about two minutes after the faucet sent the payment, with confirmations set to 1 (observed wall-clock time; it depends on network block time and the scanner's 30-second polling interval).
- **Automated test suite**: the automated test suite passes (`cargo test`), including injection, CSRF, header, rate-limit, and no-leak tests.
- **Key security**: The server holds only an incoming viewing key; no seed or spending key is ever handled. Invoice addresses are derived per invoice index from that key and mapped back to the invoice without memos. VeilGate's scanner reads compact blocks, which carry no memos, so it neither reads nor stores them; a holder of the viewing key could read memos by downloading full transactions.
- **Privacy hygiene**: No third-party requests from the checkout pages; strict CSP; no request logging; no IPs, addresses, txids or amounts logged; rate-limit keys are salted hashes of the client identity.

### Untested (Stated Plainly)

- Paying from a real wallet app by scanning the QR or opening the link.
- Mainnet.
- Reorgs deeper than 20 blocks.
- Mempool (0-confirmation) detection.
- Multiple merchants.

### Known Limits

- Testnet only.
- Single merchant.
- The free Render instance sleeps after about 15 minutes and wakes in about 50 seconds.
- Its disk is not persistent so invoices can reset.
- Scanner catches up in 500-block chunks.
- Customers need a wallet that supports the current network upgrade.
- The demo and pay pages contain plain links to two third-party testnet faucets; following them leaves VeilGate and the faucet operator sees any address pasted there.
- The hosting platform may keep its own request logs; the VeilGate application itself does not log requests.
- We have not verified how the hosting platform sets the forwarded client address header; if it adds more than one proxy, all visitors may share one rate-limit bucket.
- The public testnet explorers we tried did not display our test transactions (we did not determine why), so no explorer screenshot of our own transaction is included; the demo video uses a mainnet fully shielded transaction purely as a labelled illustration of what an observer sees.

## Run Locally

The Cargo project lives in `backend/`, so run every `cargo` command below from that directory:

```bash
cd backend
```

Defaults used below (verified from the source and `--help`): the server listens on `127.0.0.1:8080`, reads the viewing key from `.veilgate/merchant-viewing-key.txt` and stores its database at `.veilgate/veilgate.db`, all relative to the directory you run the command in (so `backend/.veilgate/` here).

### 1. Generate a Testnet Merchant Key

Run this once, from `backend/`:

```bash
cargo run --bin keygen -- --network test
```

keygen prints a 24-word recovery phrase. Write it down on paper, offline, and never share it: anyone who has it can spend the funds. keygen asks you to type `written` to confirm, does not save the phrase to disk and never shows it again. It saves only the watch-only incoming viewing key to `.veilgate/merchant-viewing-key.txt` (change this with `--output`). The server only ever reads that viewing key file; it never sees the phrase, a seed or a spending key.

### 2. Run the Server

From `backend/`, start the server with the demo checkout enabled:

```bash
cargo run --bin server -- --demo
```

Access the application at `http://127.0.0.1:8080`. The demo checkout is at `http://127.0.0.1:8080/demo`.

To use the merchant dashboard at `/merchant`, first run `cargo run --bin server -- --hash-password`, then start the server with the printed Argon2id hash in the `VEILGATE_PASSWORD_HASH` environment variable. Without it, dashboard login is disabled.

### Configuration Flags and Environment Variables

VeilGate is configured via environment variables or command-line flags:

- `VEILGATE_VIEWING_KEY`: The encoded incoming viewing key string. Takes precedence over `--key-path`. Never logged or printed.
- `PORT`: Listen port (e.g. `10000`). When set, the server listens on `0.0.0.0:$PORT` unless overridden by `--listen`.
- `VEILGATE_DB_PATH`: Path to SQLite database file (default: `.veilgate/veilgate.db`).
- `VEILGATE_TRUSTED_PROXY_HEADER`: Reverse proxy header to trust for client identity (e.g. `x-forwarded-for`).
- `VEILGATE_DEMO`: Set to `1` or `true` to enable the testnet demo checkout at `/demo`.
- `VEILGATE_CONFIRMATIONS`: Confirmations required before marking invoices paid (default: `3`).
- `VEILGATE_LIGHTWALLETD_URL`: lightwalletd gRPC TLS endpoint (default: `https://testnet.zec.rocks:443`).
- `VEILGATE_REPO_URL`: Optional GitHub repository URL displayed in the page footer.
- `VEILGATE_PASSWORD_HASH`: Argon2id hash of the merchant password for private dashboard access.
- `VEILGATE_SHOWCASE`: Optional showcase invoice configuration formatted as six comma-separated fields: `index,amount_zatoshi,public_id,scan_from_height,scan_to_height,label`. When set on a brand new, empty database, seeds this invoice, sets the address index counter to `index+1`, performs a one-time bounded background scan pass over `[scan_from_height, scan_to_height]` using lightwalletd to re-detect the real payment on startup, and sets the main cursor to `tip - 100`. The label is the last field and must not contain commas. If malformed or if the database is not empty, it is safely ignored.

Equivalent CLI flags:
- `--listen <ADDR>`: Socket address to bind (default: `127.0.0.1:8080`; the `PORT` or `VEILGATE_LISTEN` environment variables also work).
- `--db-path <PATH>`: Path to SQLite database file (default: `.veilgate/veilgate.db`).
- `--key-path <PATH>`: Path to file containing encoded incoming viewing key (default: `.veilgate/merchant-viewing-key.txt`).
- `--confirmations <N>`: Confirmations required before marking invoices paid.
- `--lightwalletd-url <URL>`: lightwalletd gRPC endpoint.
- `--demo`: Enable demo mode at `/demo`.

## Reverse Proxy and Client Identity

When running behind a reverse proxy (such as Render, Cloudflare, or an ingress controller), set:

```bash
VEILGATE_TRUSTED_PROXY_HEADER=x-forwarded-for
```

When configured, VeilGate inspects the last comma-separated entry of the `X-Forwarded-For` header. Because each proxy hop appends the client address it observed to the end of the header, the last entry represents the IP address appended by the nearest trusted reverse proxy. This ensures accurate per-client rate limiting while preventing client IP spoofing via attacker-supplied initial header values.

If `VEILGATE_TRUSTED_PROXY_HEADER` is not configured, proxy headers are ignored and the direct TCP peer address is used. Rate-limit keys are salted hashes of the client identity; raw IP addresses are never logged or stored.

## Health Check Endpoint

Container orchestrators and load balancers can query the health endpoint:

```http
GET /healthz
```

Returns `200 OK` with body `ok`. Scanner and block data are never exposed through this endpoint. Responses are served with `Cache-Control: no-store` and `X-Robots-Tag: noindex`.

## Deployment

A multi-stage `Dockerfile` and `render.yaml` blueprint are provided for containerized deployment on PaaS providers like Render. For complete instructions on container builds, secrets configuration, and memory limits, see [DEPLOY.md](docs/DEPLOY.md).

## Automated Tests

Run the automated test suite:

```bash
cargo test
```

The automated test suite passes (`cargo test`), verifying injection defense, CSRF token validation, security response headers, client identity rate-limiting, and leak prevention.

## Track

Zecathon 2026, Shielded Payments track.

## License

VeilGate is open source software licensed under the MIT License. See [LICENSE](LICENSE).

## Attributions and Licenses

The user interface includes inline SVGs adapted from Lucide icons, licensed under the ISC License:

```text
ISC License

Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2022 as part of Feather (MIT). All other copyright (c) 2022-present Lucide Contributors.

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```
