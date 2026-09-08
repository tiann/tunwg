# Push relay on the tunwg server

Linux + Docker Compose v2. tunwg keeps public TCP 80/443 and UDP 443. Caddy
terminates TLS for the Push domain on loopback TCP 8443, and the HAPI Push
relay accepts HTTP on loopback TCP 8790.

```text
Hub --HTTPS :443--> tunwg --TLS + PROXY v1--> Caddy :8443
                                            |
                                      HTTP + real client IP
                                            |
                                      Push relay :8790 --> APNs
```

Push traffic uses the host TCP stack and does not consume the WireGuard
quota. Caddy and Apple still carry the hub's encrypted notification envelope.

## Prepare

For an existing installation, merge this example into the **existing Compose
file and project**, keeping its directory/project name. Copy `Caddyfile` next
to that file and merge the `.env.example` values into your local `.env`.
Starting a second Compose project would leave two tunwg servers competing for
80/443. Preserve the existing signing secret and point `TUNWG_DATA_DIR` at
the existing absolute data path; the bind mount refuses to create a missing
directory. The stored keys and access state keep existing URLs and quotas.

For a fresh installation, copy the example directory outside the source tree,
copy `.env.example` to `.env`, and create the empty data directory named there.

Build the new tunwg image from the **tunwg repository root**:

```sh
docker build -t tunwg:sni-local .
```

Set `TUNWG_IMAGE=tunwg:sni-local`, or use a published fixed commit SHA tag
containing static SNI support. An old image will not understand these settings.
The root `.dockerignore` excludes deployment files and local access state from
the build context.

Fill in the remaining `.env` values:

- `PUSH_DOMAIN`: the public hostname, default `push.hapi.run`.
- `HAPI_PUSH_RELAY_CONTEXT`: the absolute path to the HAPI repository's `relay/`
  directory. The Compose file builds its existing Dockerfile.
- `APNS_KEY_P8_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`: credentials for the installed
  iOS app's Apple developer team. The `.p8` is mounted read-only and must be
  readable by the image's `bun` user (normally UID 1000).
- `APNS_BUNDLE_ID`: the installed app's bundle ID; current HAPI uses `run.hapi.app`.
- `APNS_ENV`: `production` for TestFlight/App Store, `sandbox` for development
  signing. This relay instance serves one environment.

Point the Push domain's A record at the relay's public IP. For the supplied
defaults: `push.hapi.run A 43.130.231.139`. Use DNS only with Cloudflare; any
AAAA record must also reach this server. Caddy validates certificates through
public TCP 443 using TLS-ALPN-01. HTTP-01 is disabled, so the existing tunwg
HTTP challenge path on TCP 80 needs no changes.

## Start and verify

From the deployment directory:

```sh
docker compose config --quiet
docker compose build push-relay
docker compose run --rm --no-deps caddy caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile
docker compose up -d
docker compose ps
docker compose logs --tail=50 tunwgs caddy push-relay
```

Updating tunwg briefly disconnects existing tunnels; clients reconnect. Caddy
waits for the Push container's health check and persists certificates under
`./caddy-data`. It listens only on `127.0.0.1:8443`, with HTTP/3, automatic HTTP
redirects, and its administration endpoint disabled.

For the default Push domain:

```sh
curl -fsS https://push.hapi.run/health
```

Expect JSON containing `"service":"hapi-push-relay"`. This checks HTTP/TLS
availability; verify APNs credentials with an actual iOS notification. Also
check that an existing hub's relay URL remains accessible. Observe Caddy
certificate/renewal errors, tunwg `static SNI backend unavailable` logs, Push
delivery outcomes, and container restart/health status.

The Hub defaults to `https://push.hapi.run`. For another domain, configure the
machine running the Hub with `HAPI_IOS_PUSH=relay` and
`HAPI_PUSH_RELAY_URL=https://your-push-domain`.

## Real client IPs

`TUNWG_SNI_PROXY_PROTOCOL=true` makes tunwg attach the original source address
to every static TLS connection. Caddy requires and decodes that header before
TLS, then overwrites `X-Forwarded-For`. The Push relay uses it for IP rate
limiting through `RELAY_TRUST_PROXY=true`. The two backend ports stay on
loopback; the API and ordinary tunnels retain their existing address handling.

The Caddy listener requires PROXY protocol, so a direct TLS request to port
8443 will fail. Check it through the public tunwg route instead.

## Roll back

Restore the previous tunwg image and Compose configuration, then recreate the
`tunwgs` service in the same project. Stop the added `caddy` and `push-relay`
services if reverting the complete deployment. Keep both data directories and
the existing signing secret. Static routing does not change persistent state
formats, so no data migration is needed.
