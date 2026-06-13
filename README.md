<div align="center">

<img src="https://dogukangecko.github.io/netnazar-relay/netnazar-icon.png" width="120" alt="NetNazar" />

# 🧿 NetNazar Relay

**Self-hosted relay + protocol for [NetNazar](https://dogukangecko.github.io/netnazar/) — the privacy-first network scanner.**

No vendor cloud. You run the server. Your data never leaves infrastructure you control.

[Relay site](https://dogukangecko.github.io/netnazar-relay/) · [NetNazar app](https://dogukangecko.github.io/netnazar/) · [Privacy](https://dogukangecko.github.io/netnazar/privacy.html) · License: **AGPL-3.0**

</div>

---

## What is this?

NetNazar is a local network scanner & monitor (device discovery, connectivity metrics, security audit, hidden-camera scan, network map) for iPhone, iPad, Mac and Android. Everything runs **on your device** — there is no vendor cloud.

For **optional remote monitoring** (watch your home network from outside, reach device web UIs), NetNazar uses a relay that **you self-host**. This repository contains exactly that server, so you can read, audit, build and run it yourself:

- **`netscan-relay`** — the relay server (Rust · [axum](https://github.com/tokio-rs/axum) + [sqlx](https://github.com/launchbadge/sqlx)/PostgreSQL). Receives inventory/metrics pushes from your agent, serves them back to your app, dispatches away-notifications to **your own** channels (ntfy, webhook, Telegram, Discord, Slack, Pushover, Gotify, SMTP), keeps a hash-chained audit log, and offers a read-only web panel and a reverse-tunnel to device web UIs.
- **`netscan-proto`** — the wire types exchanged between the agent and the relay (the documented protocol).

> ### Open-core
> The relay and protocol are open source (AGPL-3.0) so the component running on **your** server is fully auditable. The NetNazar **app** and the **scanning engine** (`netscan-core`) are proprietary and ship through the App Store / Google Play / signed desktop builds. The **agent** that pushes data is distributed as a binary/Docker image.

## Why self-host?

- **Zero data-custody.** We never receive your scan data. The relay you run does — and only that.
- **No third party.** Away-notifications go through channels you configure (your ntfy, your Telegram bot…).
- **Auditable.** Read every line. Verify there is no telemetry, no phone-home, no hidden sink.

## Quick start (Docker)

No compiling needed — `docker-compose.yml` pulls a **prebuilt multi-arch image** (`linux/amd64` + `linux/arm64`, so it runs on a Raspberry Pi / ARM NAS as-is) from GHCR:

```bash
git clone https://github.com/dogukangecko/netnazar-relay.git
cd netnazar-relay

# Strongly recommended: set a real DB password in production.
export NETSCAN_DB_PASSWORD="$(openssl rand -hex 16)"

docker compose up -d              # pulls ghcr.io/dogukangecko/netnazar-relay + PostgreSQL on :8765
```

Or pull the image directly: `docker pull ghcr.io/dogukangecko/netnazar-relay:latest`.

The relay listens on `:8765` (an uncommon port, chosen so it won't clash with the many apps that use 8080; change it with `NETSCAN_RELAY_PORT`). PostgreSQL is **not** published to the host at all — the relay reaches it over the internal Docker network, so there is no 5432 conflict either. It applies its schema migrations automatically on startup. Point your agent's `NETSCAN_RELAY_URL` at it, then log in from the NetNazar app's remote view.

> Prefer to build it yourself? Uncomment the `build:` line in `docker-compose.yml` and run `docker compose up -d --build`.

## Build from source

```bash
cargo build --release -p netscan-relay
NETSCAN_DATABASE_URL=postgres://netscan:netscan@localhost:5432/netscan \
  ./target/release/netscan-relay            # runs the server
```

### CLI helpers

The same binary doubles as an admin CLI:

```bash
netscan-relay enroll                          # create an agent id + key (push credentials)
netscan-relay create-user --email you@example.com --password '...'
netscan-relay add-channel --kind ntfy ...     # wire up an away-notification channel
```

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `NETSCAN_DATABASE_URL` | ✅ | — | PostgreSQL connection string |
| `NETSCAN_BIND` | | `0.0.0.0:8765` | listen address |
| `NETSCAN_DB_PASSWORD` | | `netscan` | used by `docker-compose.yml` (change in prod) |

Secrets (DB URL, channel tokens) are read from the environment / per-channel config — **never hardcoded**.

## How it works

```
 your network                         your server                 your phone
┌──────────────┐   push (HTTPS)   ┌──────────────────┐   read   ┌──────────────┐
│ NetNazar     │ ───────────────▶ │  netscan-relay   │ ───────▶ │ NetNazar app │
│ agent (scan) │   inventory,     │  + PostgreSQL    │  login,  │ (remote view)│
│              │   metrics        │                  │  events  │              │
└──────────────┘                  └──────────────────┘          └──────────────┘
        outbound-only          REST + WebSocket (axum)        opaque session token
```

- **Inventory / metrics** are pushed by the agent (`POST /v1/inventory`, `/v1/metrics`) authenticated with an agent key.
- **The app** logs in (`POST /v1/login` → opaque, hashed, expiring session token) and reads networks, devices, metrics, outages, events, and the audit log.
- **Away-notifications** are dispatched best-effort to the tenant's enabled channels when a new device appears.
- **Reverse tunnel** (`/v1/agent/tunnel` WebSocket + `/v1/networks/{id}/proxy/...`) lets the app reach a device's web UI through the relay, with an SSRF guard restricting the agent to private IPv4.
- Multi-tenant from day one (`tenant_id` everywhere, RLS-ready schema).

Browse the source for the full endpoint list — `netscan-relay/src/routes.rs`.

## License

[AGPL-3.0](LICENSE). If you run a modified relay as a network service, you must offer your users its source. This is intentional: NetNazar is self-host first, and no one should be able to turn it into a closed vendor cloud.

The NetNazar application and scanning engine are **not** covered by this license and remain proprietary.

---

<div align="center">© 2026 NetNazar 🧿 — built by <a href="https://github.com/dogukangecko">@dogukangecko</a></div>
