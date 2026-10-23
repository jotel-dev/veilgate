# VeilGate

Privacy-first shielded payment checkout for merchants. Built for Zecathon 2026 (Shielded Payments track). Testnet only.

Live demo: https://veilgate-demo.onrender.com

The hosted merchant dashboard is private and is demonstrated in the submission video. The instructions below allow anyone to run their own local instance and merchant dashboard.

## Try It in Three Steps

1. Open the demo checkout page at https://veilgate-demo.onrender.com/demo
2. Create a 0.1 invoice.
3. Copy the derived payment address, paste it into a testnet faucet such as [faucet.testnet.valargroup.dev](https://faucet.testnet.valargroup.dev) or [fauzec.com](https://fauzec.com), and watch the invoice turn Paid.

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
- **Automated test suite**: 95 automated tests pass (`cargo test`), including injection, CSRF, header, rate-limit, and no-leak tests.
- **Key security**: The server holds only an incoming viewing key; no seed or spending key is ever handled. Invoice addresses are derived per invoice index from that key and mapped back to the invoice without memos. VeilGate's scanner reads compact blocks, which carry no memos, so it neither reads nor stores them; a holder of the viewing key could read memos by downloading full transactions.
- **Zero data leakage**: No third-party requests from the checkout pages; strict CSP; no request logging; no IPs, addresses, txids or amounts logged; rate-limit keys are salted hashes of the client identity.

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
- The public testnet explorers we tried did not display our test transactions (we did not determine why), so no explorer screenshot of our own transaction is included; the demo video uses a mainnet fully shielded transaction purely as a labelled illustration of what an observer sees.

## Run Locally

### 1. Generate a Testnet Merchant Key

Generate a dedicated incoming viewing key for local testing. Run keygen with `--network test`:

```bash
cargo run --bin keygen -- --network test --output .veilgate/viewing-key.txt
```

VeilGate only ever handles the generated incoming viewing key. Seed phrases and spending keys are never handled or loaded by the server.

### 2. Run the Server

Start the local server with demo mode enabled:

```bash
cargo run --bin server -- --key-path .veilgate/viewing-key.txt --demo
```

Access the application at `http://127.0.0.1:3000`.

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
- `--listen <ADDR>`: Socket address to bind (default: `127.0.0.1:3000`).
- `--db-path <PATH>`: Path to SQLite database file.
- `--key-path <PATH>`: Path to file containing encoded incoming viewing key.
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

95 automated tests pass, verifying injection defense, CSRF token validation, security response headers, client identity rate-limiting, and leak prevention.

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
