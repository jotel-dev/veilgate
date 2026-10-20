# VeilGate

Privacy-first shielded payment checkout for merchants. Built for Zecathon 2026 (Shielded Payments track). Testnet only.

## Configuration

VeilGate is configured via environment variables or command-line flags:

- `VEILGATE_VIEWING_KEY`: The encoded incoming viewing key. Takes precedence over `--key-path`. Never logged or printed.
- `PORT`: Listen on `0.0.0.0:$PORT` when `--listen` is not passed on the command line.
- `VEILGATE_DB_PATH`: Path to SQLite database (default: `.veilgate/veilgate.db`). Parent directories are created automatically.
- `VEILGATE_TRUSTED_PROXY_HEADER`: Reverse proxy header to trust for client identity (e.g. `x-forwarded-for`).
- `VEILGATE_DEMO`: Set to `1` or `true` to enable testnet demo checkout at `/demo`.
- `VEILGATE_CONFIRMATIONS`: Confirmations required before marking invoices paid (default: `3`).
- `VEILGATE_LIGHTWALLETD_URL`: lightwalletd gRPC TLS endpoint (default: `https://testnet.zec.rocks:443`).
- `VEILGATE_REPO_URL`: Optional GitHub repository URL for footer link.
- `VEILGATE_PASSWORD_HASH`: Argon2id hash of merchant password for dashboard access.

## Reverse Proxy and X-Forwarded-For

When running behind a reverse proxy (such as Render, Cloudflare, or an ingress controller), set:

```bash
VEILGATE_TRUSTED_PROXY_HEADER=x-forwarded-for
```

When this is set, VeilGate uses the **LAST** comma-separated entry of the `X-Forwarded-For` header. Because each proxy hop appends the client address it observed to the end of the header, the last entry represents the IP address appended by the nearest trusted reverse proxy. This ensures accurate per-client rate limiting while preventing client IP spoofing via attacker-supplied initial header values.

If `VEILGATE_TRUSTED_PROXY_HEADER` is not configured, all proxy headers are ignored and the direct TCP peer address is used.

## Health Check Endpoint

Container orchestrators and load balancers can query the health endpoint:

```http
GET /healthz
```

Returns `200 OK` with body `ok`. Scanner and block data are never exposed through this endpoint. Responses are served with `Cache-Control: no-store` and `X-Robots-Tag: noindex`.

## Container Deployment

A multi-stage `Dockerfile` and `render.yaml` blueprint are provided for containerized deployment on PaaS providers like Render. For detailed instructions, memory limits, and instructions on pushing pre-built images, see [DEPLOY.md](docs/DEPLOY.md).

## Attributions and Licenses

The user interface includes inline SVGs adapted from Lucide icons, licensed under the ISC License:

```text
ISC License

Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2022 as part of Feather (MIT). All other copyright (c) 2022-present Lucide Contributors.

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```
