# VeilGate Deployment Guide

This guide describes how to deploy VeilGate as a Docker container on PaaS providers like Render.

## Overview

VeilGate is a privacy-first merchant checkout server for Zcash shielded payments. The server runs as a self-contained web application and background scanner.

## Configuration (Environment Variables)

The server is configured entirely through environment variables:

| Variable | Description | Default / Example |
|---|---|---|
| `VEILGATE_VIEWING_KEY` | Encoded incoming viewing key (Orchard/unified). Takes precedence over `--key-path`. Never logged or printed. | Secret |
| `PORT` | Port to listen on (`0.0.0.0:$PORT`) when `--listen` is not passed on the command line. | `10000` (Render default) or `8080` |
| `VEILGATE_DB_PATH` | Path to SQLite database file. Parent directories are created automatically. | `/app/data/veilgate.db` |
| `VEILGATE_TRUSTED_PROXY_HEADER` | Proxy header to trust for client IP rate-limiting (`x-forwarded-for`). | `x-forwarded-for` |
| `VEILGATE_DEMO` | Enables `/demo` testnet invoice generator when set to `1` or `true`. | `1` |
| `VEILGATE_CONFIRMATIONS` | Required block confirmations to mark invoices as Paid. | `3` |
| `VEILGATE_LIGHTWALLETD_URL` | gRPC TLS endpoint for lightwalletd. | `https://testnet.zec.rocks:443` |
| `VEILGATE_REPO_URL` | Optional link to repository shown in footer. | Optional |
| `VEILGATE_PASSWORD_HASH` | Argon2id hash of merchant password for dashboard access. | Secret |

## Memory Limit and Build Considerations (Free PaaS)

Compiling VeilGate from source involves cryptographic dependencies (`zcash_client_backend`, `zcash_keys`, `halo2_proofs`, `pasta_curves`, `ring`, `tonic`). During compilation, rustc and LLVM typically require between 1.5 GB and 2.5 GB of peak RAM.

Free PaaS tiers (such as Render Free) provide 512 MB of RAM. Compiling directly on the host is expected to:
1. Exceed the 512 MB memory limit and be killed by the Linux Out-Of-Memory (OOM) killer (exit code 137).
2. Take an excessively long time (15 to 30 minutes) if it swaps or throttles.

### Recommended Approach: Build Locally and Push to Container Registry

To avoid build-time memory exhaustion on 512 MB hosts, build the container image on your local machine or in a CI pipeline (e.g., GitHub Actions) and push it to a container registry. The host then pulls the pre-built image directly.

#### Step 1: Build the Docker Image Locally

Run the following command from the repository root:

```bash
docker build -t your-registry-username/veilgate:latest .
```

#### Step 2: Push the Image to a Registry

Authenticate and push to Docker Hub:

```bash
docker login
docker push your-registry-username/veilgate:latest
```

Alternatively, push to GitHub Packages (ghcr.io):

```bash
docker tag your-registry-username/veilgate:latest ghcr.io/your-github-username/veilgate:latest
docker push ghcr.io/your-github-username/veilgate:latest
```

#### Step 3: Deploy Pre-built Image on Render

In the Render Dashboard:
1. Click **New +** and select **Web Service**.
2. Choose **Deploy an existing image from a registry**.
3. Enter your image URL (e.g. `docker.io/your-registry-username/veilgate:latest` or `ghcr.io/your-github-username/veilgate:latest`).
4. Select the **Free** instance type.
5. In **Advanced**, set **Health Check Path** to `/healthz`.
6. Add the environment variables described above. Ensure `VEILGATE_VIEWING_KEY` and `VEILGATE_PASSWORD_HASH` are set as secret environment variables.

## Deploying via Blueprint (render.yaml)

The repository includes a `render.yaml` specification for Render Blueprints.

When creating a Blueprint:
1. Connect your repository to Render.
2. Render reads `render.yaml` and provisions the web service.
3. Because `VEILGATE_VIEWING_KEY` and `VEILGATE_PASSWORD_HASH` are marked with `sync: false`, Render prompts you to input these secrets securely in the dashboard.

## Reverse Proxy and IP Resolution

When running behind reverse proxies (like Render or Cloudflare), set:

```bash
VEILGATE_TRUSTED_PROXY_HEADER=x-forwarded-for
```

VeilGate reads the `X-Forwarded-For` header and uses the **LAST** comma-separated entry (appended by the nearest trusted reverse proxy) to identify the client IP for rate-limiting. This prevents IP spoofing while correctly rate-limiting users behind proxies.

## Ephemeral Disks and Scanner Synchronization

On free hosting tiers without persistent disks, the filesystem resets on container restart:
- When a fresh database is initialized, VeilGate automatically begins scanning at the current chain tip minus 100 blocks (`tip - 100`).
- The `/demo` page includes a notice to users: "This demo instance may reset. Invoices are not guaranteed to persist."
- Parent directories for the SQLite database are created automatically if they do not exist.

## Health Check Endpoint

VeilGate provides a dedicated health check endpoint:

```http
GET /healthz
```

- Returns HTTP status `200` with plain text body `ok`.
- Contains no scanner, block, or payment details.
- Responses include `Cache-Control: no-store` and `X-Robots-Tag: noindex`.
- Requests are rate-limited per client identity.
