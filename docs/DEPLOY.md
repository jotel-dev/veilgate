# VeilGate Deployment Guide

This guide describes how to deploy VeilGate as a prebuilt container image to Render or another PaaS provider without needing Docker installed on your local machine.

## Overview

VeilGate is a privacy-first merchant checkout server for Zcash shielded payments. Because compiling Rust cryptographic libraries requires significant RAM (1.5 GB to 2.5 GB peak memory) that exceeds free PaaS build limits (512 MB), container images are built automatically via GitHub Actions and published to the GitHub Container Registry (`ghcr.io`). Render then pulls the prebuilt image directly.

## Deployment Steps (No Local Docker Required)

Follow these exact steps in order to deploy a live instance:

### Step 1: Push to main

Ensure your local commits are ready and push them to the `main` branch of your GitHub repository:

```bash
git push origin main
```

The GitHub Actions workflow (`.github/workflows/docker.yml`) triggers automatically on changes to `backend/**`, `Dockerfile`, `.dockerignore`, or the workflow file.

### Step 2: Watch the Actions run

1. Go to your repository on GitHub: `https://github.com/jotel-dev/veilgate`.
2. Click on the **Actions** tab.
3. Select the running **Docker** workflow.
4. The workflow performs the following automated steps:
   - Runs `cargo test` across the full test suite so a broken commit never produces an image.
   - Builds the minimal multi-stage container image using Docker Buildx and GitHub Actions cache.
   - Pushes two image tags to GitHub Packages: `ghcr.io/jotel-dev/veilgate:latest` and `ghcr.io/jotel-dev/veilgate:sha-<shortsha>`.
   - Runs the built container image in a shell audit step to verify that `.veilgate`, any `.db` file, any `.env` file, and `docs/design` are absent from the container filesystem.
5. Wait for the workflow run to complete with a green success status.

### Step 3: Make the ghcr.io package public

By default, new container packages published to GitHub Packages are private. To allow Render to pull the prebuilt image without configuring registry credentials:

1. Navigate to the repository page on GitHub.
2. In the right-hand column under **Packages**, click on **veilgate** (or navigate to `https://github.com/jotel-dev/veilgate/pkgs/container/veilgate`).
3. Click **Package settings** in the right sidebar.
4. Scroll down to the **Danger Zone** section and click **Change visibility**.
5. Select **Public**, type the package name to confirm, and save changes.

### Step 4: Create the Render web service from the image

You can deploy the prebuilt image on Render using either the Blueprint or the Render Dashboard:

#### Option A: Using the Blueprint (render.yaml)
1. In the [Render Dashboard](https://dashboard.render.com), click **New +** and select **Blueprint**.
2. Connect your `jotel-dev/veilgate` repository.
3. Render reads `render.yaml`, recognizing `runtime: image` with image URL `ghcr.io/jotel-dev/veilgate:latest` on the Free plan with `/healthz` health checks.
4. Render prompts you to populate the secret environment variables (`sync: false`).

#### Option B: Creating a Web Service Manually
1. In the Render Dashboard, click **New +** and select **Web Service**.
2. Under source options, select **Existing Image**.
3. In the Image URL field, enter:
   ```text
   ghcr.io/jotel-dev/veilgate:latest
   ```
4. Click **Connect**.
5. Set Name to `veilgate`, Region to your preference, and select the **Free** instance type.
6. In **Advanced**, set **Health Check Path** to `/healthz`.

### Step 5: Set secret environment variables in the Render dashboard

Under the service's **Environment** tab in the Render Dashboard, configure the following secret variables:

1. `VEILGATE_VIEWING_KEY`:
   - Paste the encoded incoming viewing key for your hosted demo instance.
   - **Never commit this viewing key or paste it into repository files.**
   - See the "Create a separate demo key" section below for instructions on generating a dedicated demo key.
2. `VEILGATE_PASSWORD_HASH`:
   - Paste the Argon2id hash of your merchant dashboard password.
   - **Never commit password hashes or plaintext passwords into git.**

### Step 6: Configure non-secret environment variables

Ensure the following environment variables are set in the Render Dashboard (preconfigured when using `render.yaml`):

| Variable | Recommended Value | Description |
|---|---|---|
| `PORT` | `10000` | Render standard port. Server listens on `0.0.0.0:$PORT`. |
| `VEILGATE_DEMO` | `1` | Enables the `/demo` testnet invoice generator and faucet links. |
| `VEILGATE_CONFIRMATIONS` | `3` | Required testnet block confirmations to mark invoices as Paid. |
| `VEILGATE_TRUSTED_PROXY_HEADER` | `x-forwarded-for` | Uses the last entry of `X-Forwarded-For` for client rate limiting. |
| `VEILGATE_LIGHTWALLETD_URL` | `https://testnet.zec.rocks:443` | gRPC TLS endpoint for the testnet lightwalletd service. |
| `VEILGATE_DB_PATH` | `/app/data/veilgate.db` | Path to SQLite database file on container filesystem. |
| `VEILGATE_REPO_URL` | `https://github.com/jotel-dev/veilgate` | Link to public repository displayed in web footer. |
| `VEILGATE_SHOWCASE` | *(optional)* | Six comma-separated fields: `index,amount_zatoshi,public_id,scan_from_height,scan_to_height,label`. On a brand new, empty database, seeds this showcase invoice, advances `next_address_index` to `index+1`, runs a one-time bounded background scan pass over `[scan_from_height, scan_to_height]` to re-detect the payment, and sets the main cursor to `tip - 100` without blocking web startup. The label must not contain commas. |

### Step 7: Check /healthz

Once Render deploys the container:

1. Visit your service health check endpoint:
   ```text
   https://<your-service-name>.onrender.com/healthz
   ```
2. Verify that it returns HTTP status `200` with response body `ok`.
3. The response includes `Cache-Control: no-store` and `X-Robots-Tag: noindex`, and contains zero scanner or payment state data.
4. Visit your service homepage (`https://<your-service-name>.onrender.com/`) and test invoice creation on the `/demo` page (`https://<your-service-name>.onrender.com/demo`).

---

## Create a Separate Demo Key

Before launching the hosted demo, generate a separate viewing key dedicated exclusively to the hosted instance:

```bash
cargo run --bin keygen -- --network test --output .veilgate/demo-viewing-key.txt
```

### Why a Separate Demo Key is Mandatory

The hosted demo instance **must NOT reuse the local merchant key**.

VeilGate derives individual shielded payment addresses deterministically from the incoming viewing key using sequential index numbers (starting at index 2). If two instances (for example, your local development server and the hosted demo on Render) share the same viewing key:
1. Both instances will derive the exact same payment addresses for invoice #1, #2, etc.
2. When a customer or tester pays an address generated by the demo, both servers would detect the payment.
3. Database states, confirmations, invoice IDs, and payment totals would collide, creating race conditions and corrupted invoice accounting.

Keep key files secure:
- The `.veilgate/` directory is excluded by `.gitignore` and `.dockerignore`.
- Open `.veilgate/demo-viewing-key.txt`, copy the encoded viewing key string, and paste it directly into Render's `VEILGATE_VIEWING_KEY` environment variable in the web dashboard.
- Never commit `.veilgate/` or any key files to source control.

---

## Technical Details: Render and Container Registry

### Blueprint Image Keys

Render Blueprint (`render.yaml`) specifies container images using:
- `runtime: image`: Informs Render that the service is image-backed rather than built from source.
- `image.url`: Specifies the full URL to the container image (e.g., `ghcr.io/jotel-dev/veilgate:latest`).
- `healthCheckPath`: Points to `/healthz` for zero-downtime health probing.

### Public Registry Access

Render pulls images from public container registries (including public GitHub Container Registry packages at `ghcr.io`) without requiring any registry credentials or Docker logins. As long as the package visibility is set to Public in GitHub package settings, Render can fetch and run the image directly.

### Operational Limits on Render Free Tier

1. **No Auto-Deploy on Registry Push**: Image-backed services on Render do not automatically redeploy when a new tag is pushed to `ghcr.io`. To redeploy after an image build:
   - In the Render dashboard, click **Manual Deploy** -> **Deploy latest commit** (or **Clear build cache & deploy**).
   - Alternatively, configure a Deploy Hook URL in Render and trigger it from your CI pipeline.
2. **Registry Caching on Mutable Tags**: Render caches public images. When redeploying the `:latest` tag, select **Clear build cache & deploy** to ensure Render pulls the newly pushed image, or update the blueprint to use the immutable commit tag (`:sha-<shortsha>`).
3. **Inactivity Sleep**: Free tier web services spin down after 15 minutes without incoming HTTP traffic. The subsequent incoming request will experience a cold-start delay of approximately 50 seconds while the container initializes.
4. **Ephemeral Filesystem**: Free instances do not have persistent disk storage. When the service spins down or redeploys, the SQLite database is reset. VeilGate handles this cleanly: on every fresh database start, the background scanner begins scanning at chain tip minus 100 blocks (`tip - 100`), ensuring rapid synchronization without scanning the entire history of the testnet.
5. **Memory Constraint**: Free instances provide 512 MB of RAM. VeilGate's runtime server and scanner consume approximately 40 MB to 70 MB of RSS memory, operating comfortably within the 512 MB limit.
