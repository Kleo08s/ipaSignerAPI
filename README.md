# IPA Signer

A Node.js API that signs `.ipa` files with your own certificate (`.p12`) and provisioning profile (`.mobileprovision`), and gives you a link to install the signed app directly on an iPhone or iPad.

Signing is done by [zsign](https://github.com/zhlynn/zsign), which is compiled into the Docker image.

> Only use this tool with certificates and profiles that you own (or are authorized to use).

## Features

- `POST /sign` with a multipart form: signs the IPA and returns the install URL (`itms-services://`)
- Automatic `manifest.plist` generation, reading the bundle id, version and name from the IPA
- Install page with a button (`/install/:id`) to open in Safari
- Automatic cleanup: after one hour (configurable) the original IPA, signed IPA, `.mobileprovision`, `.p12` and manifest are all deleted
- Separate size limits for the IPA, the `.mobileprovision` and the `.p12`
- Rate limiting per IP and globally
- The p12 is checked before signing, with a clear error if the password is wrong, and p12 files using old ciphers are converted automatically

## Requirements

- Docker and Docker Compose (recommended), or Node.js 18+ with [zsign](https://github.com/zhlynn/zsign) and `openssl` installed
- A domain with **valid HTTPS**: iOS refuses OTA installation from non-HTTPS URLs or invalid certificates

## Quick start (Docker Compose)

```bash
git clone https://github.com/OWNER/ipa-signer.git
cd ipa-signer
cp .env.example .env      # set at least DOMAIN
docker compose up -d
```

The `docker-compose.yml` uses the image published on GitHub Packages (`ghcr.io/OWNER/ipa-signer:latest`). To build it locally instead:

```bash
docker compose up -d --build
```

Remember to replace `OWNER` with your GitHub username or organization (lowercase).

### Without Docker

```bash
npm install
cp .env.example .env
npm start
```

`zsign` must be reachable in your `PATH` (or set `ZSIGN_PATH`).

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `DOMAIN` | **required** | Public domain used in the install URLs (e.g. `sign.example.com`). If no scheme is given, `https://` is used |
| `MAX_IPA_MB` | `500` | Maximum size of the uploaded IPA (MB) |
| `MAX_MOBILEPROVISION_MB` | `1` | Maximum size of the `.mobileprovision` (MB) |
| `MAX_P12_MB` | `1` | Maximum size of the `.p12` (MB) |
| `CLEANUP_MINUTES` | `60` | Minutes after which all files of a job are deleted |
| `RATE_LIMIT_IP_MAX` | `10` | Maximum requests to `/sign` per IP in the window (0 = disabled) |
| `RATE_LIMIT_IP_WINDOW_MINUTES` | `60` | Per-IP limit window (minutes) |
| `RATE_LIMIT_GLOBAL_MAX` | `100` | Maximum total requests to `/sign` in the window (0 = disabled) |
| `RATE_LIMIT_GLOBAL_WINDOW_MINUTES` | `60` | Global limit window (minutes) |
| `TRUST_PROXY` | `1` | Number of proxies in front of the app, used to read the real client IP (0 = none) |
| `PORT` | `3000` | Server port |
| `DATA_DIR` | `./data` | Folder for temporary files (`/data` inside the container) |
| `ZSIGN_PATH` | `zsign` | Path to the zsign binary |

> **Be careful with `TRUST_PROXY`**: if it is wrong, behind a reverse proxy every user appears to have the same IP (so the per-IP limit triggers for everyone at once), or the IP can be spoofed through `X-Forwarded-For`. With two proxy layers (e.g. a tunnel plus a reverse proxy) set it to `2`.

## API

### `POST /sign`

`multipart/form-data` form with these fields:

| Field | Type | Description |
|---|---|---|
| `ipa` | file | The app to sign (`.ipa`) |
| `mobileprovision` | file | The provisioning profile (`.mobileprovision`) |
| `p12` | file | The certificate (`.p12`) |
| `password` | text | Password of the `.p12` |

```bash
curl -X POST https://sign.example.com/sign \
  -F ipa=@app.ipa \
  -F mobileprovision=@profile.mobileprovision \
  -F p12=@cert.p12 \
  -F 'password=your-password'
```

`200` response:

```json
{
  "id": "0b6c0d3e-....",
  "installUrl": "itms-services://?action=download-manifest&url=https%3A%2F%2Fsign.example.com%2Fmanifest%2F0b6c0d3e-....plist",
  "installPage": "https://sign.example.com/install/0b6c0d3e-....",
  "manifestUrl": "https://sign.example.com/manifest/0b6c0d3e-....plist",
  "ipaUrl": "https://sign.example.com/files/0b6c0d3e-..../signed.ipa",
  "expiresAt": "2026-11-22T15:00:00.000Z"
}
```

Open `installPage` (or `installUrl`) in Safari on an iPhone or iPad to install the app.

Errors (`{"error": "..."}`):

| Code | Cause |
|---|---|
| `400` | Missing field, wrong extension, invalid IPA, wrong p12 password or unreadable p12 |
| `413` | A file exceeds the configured limit |
| `422` | Signing failed (the message contains zsign's output) |
| `429` | Rate limit exceeded (per IP or global) |

### Other endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/install/:id` | Page with the install button |
| `GET` | `/manifest/:id.plist` | OTA manifest used by iOS |
| `GET` | `/files/:id/signed.ipa` | Download the signed IPA |
| `GET` | `/health` | Healthcheck |

The `id` values are random UUIDs; after `CLEANUP_MINUTES` the endpoints return `404`.

## Security

- **There is no authentication.** If the service is public, anyone can sign using their own certificates and use up your bandwidth and disk. Use the limits in `.env` and, if needed, put it behind a reverse proxy with authentication or a token.
- The `.p12` and the profile stay on disk until the job expires (`CLEANUP_MINUTES`).
- The p12 password is passed to zsign as an argument (briefly visible in the server's process list) and to openssl through an environment variable.
- Never commit your `.env` file.

## Publishing the image to GitHub Packages

The workflow `.github/workflows/docker-publish.yml` automatically builds and publishes the image to `ghcr.io` on every push to `main` and on every `v*` tag.

1. Push the project to GitHub
2. Check the **Actions** tab: the "Publish Docker image" job starts
3. When the build finishes, the image appears under **Packages** on the repo page
4. To make it public: *Package settings → Danger Zone → Change visibility → Public*

If the package is private, the server needs to log in first:

```bash
echo "$TOKEN" | docker login ghcr.io -u YOUR_USER --password-stdin
```

(the token is a Personal Access Token with the `read:packages` scope).

## Troubleshooting

- **`mac verify failure`**: the p12 password is wrong or the file is corrupted. Check with `openssl pkcs12 -in cert.p12 -nokeys -noout`.
- **The app won't install on the iPhone**: make sure `DOMAIN` has a valid HTTPS certificate, the device UDID is included in the provisioning profile, and the certificate has not been revoked.
- **The per-IP limit triggers for everyone**: check `TRUST_PROXY`.

## Credits

- [zsign](https://github.com/zhlynn/zsign) for signing the IPAs
