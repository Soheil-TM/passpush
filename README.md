# pwpush

A single-admin, one-time secret link. The browser encrypts the secret. The server stores ciphertext and never receives the master key, the AES key, or the plaintext.

## Architecture

The administrator signs in and asks for an id. The browser generates a 256-bit master key `K` and keeps it in the URL fragment (`/p/{id}#{K}`). HKDF-SHA-256, with a 32-byte zero salt, derives two values:

- `pwpush-v1-enc` is the AES-256-GCM key
- `pwpush-v1-auth` is a 32-byte token

The browser sends the auth token once, at creation. The server stores only `SHA-256(authToken)`. Reveal sends `{id, authToken}`. The winning statement is:

```sql
DELETE FROM secrets
WHERE id=? AND auth_hash=? AND expires_at>?
RETURNING nonce, ciphertext, version
```

A wrong token matches zero rows and does not delete the secret. Unknown, expired, consumed, and wrong-token responses are the same 404 body. `PRAGMA secure_delete=ON` is set. That is not physical erasure. See the deletion section.

`GET /p/{id}` returns one fixed HTML document and does not touch SQLite. The page reads the fragment into memory, removes it with `history.replaceState`, and waits for a click. It does not reveal on load, so a chat preview does not burn the secret. A refresh after the fragment was removed has no key, so it does not call reveal and does not burn the secret. If reveal returns ciphertext and decryption then fails, the secret is already gone; the page says so.

There is one SQLite file per deployment. There is no shared multi-tenant database. Two customers means two deployments and two volumes.

## Threat model

A leaked database, log, or backup does not contain the plaintext or the master key. The full link, including the fragment, is the secret: anyone who has it can read the secret once. Knowing only the id is not enough to retrieve or burn it.

This design does not protect against a server that sends different JavaScript. The browser has to trust the page that performs HKDF and AES-GCM. That limit is inherent to this kind of tool.

The auth token is sent to the server at create and reveal. Request bodies are not logged. A process that records bodies can see the auth token and the ciphertext. It still does not get the AES key, which is derived in the browser and never sent.

Rate limits and the login lockout live in memory and reset when the process restarts. The five-failure, fifteen-minute lockout and the single-flight Argon2 check can both refuse the real administrator. `reset-admin` clears the lockout and every session.

## Requirements

- Linux
- Go 1.27.3 to build
- Node 26 to run `web/crypto.test.mjs`
- Docker, only if you use Compose
- A hostname in the certificate SAN that matches `PUBLIC_ORIGIN`
- An administrator password of at least 12 characters, in a file. Length is necessary, not sufficient.

## Environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | yes | Canonical `https` origin with no userinfo, path, query, fragment, or trailing slash. Links are built from this. The `Host` header is never used for that. When the published port is not 443, include it (`https://stm.local:8443`); otherwise the browser `Host` is rejected with 421. |
| `DATA_DIR` | yes | Directory for the SQLite file. Mode `0700`. |
| `ADMIN_PASSWORD_FILE` | yes | Password file. Read only when no administrator exists, and by `reset-admin`. |
| `TLS_MODE` | yes | `direct` or `proxy`. |
| `LISTEN_ADDR` | no | Default `:8443`. Inside a container this should stay `:8443`. |
| `TLS_CERT_FILE` | direct | Certificate PEM. Include the issuing CA in this file when the certificate is not self-signed, so the healthcheck can verify it. |
| `TLS_KEY_FILE` | direct | Private key PEM. |
| `TRUSTED_PROXY_IPS` | proxy | Comma-separated proxy IPs. Empty in proxy mode refuses to start. |
| `ARGON2_MEMORY_KIB` | no | Default and floor: `19456` (19 MiB). |
| `ARGON2_ITERATIONS` | no | Default and floor: `2`. |
| `ARGON2_PARALLELISM` | no | Default and floor: `1`. |
| `MAX_CIPHERTEXT_BYTES` | no | Default `65536`. Startup fails above `1048576` or below `16`. |

Startup also fails when the password file is missing or shorter than 12 characters and no administrator hash exists yet. A later edit of that file does not change the password. Use `reset-admin`.

Argon2id uses a 16-byte salt and a 32-byte output. One verification runs at a time. A busy verifier returns 429.

## Local development

Generate a certificate whose SAN is `stm.local`, and map that name to loopback in `/etc/hosts` if you want a browser to accept it.

```sh
mkdir -p certs secrets data
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout certs/tls.key -out certs/tls.crt \
  -subj /CN=stm.local \
  -addext subjectAltName=DNS:stm.local
printf '%s\n' 'replace-this-password' > secrets/admin_password.txt
chmod 600 secrets/admin_password.txt

export PUBLIC_ORIGIN=https://stm.local:8443
export DATA_DIR=$PWD/data
export ADMIN_PASSWORD_FILE=$PWD/secrets/admin_password.txt
export TLS_MODE=direct
export TLS_CERT_FILE=$PWD/certs/tls.crt
export TLS_KEY_FILE=$PWD/certs/tls.key
export LISTEN_ADDR=127.0.0.1:8443

CGO_ENABLED=0 go run ./cmd/server
```

Open `https://stm.local:8443/`. The page has no sign-in. Choose a lifetime in minutes, hours, or days, up to 7 days, and how many times the link can be opened, from 1 to 20. The server rejects a missing ttl, a ttl below 1 second, a ttl above 7 days (604800 seconds), and a view count outside 1 to 20.

Changing the password in the admin page, or running `reset-admin`, replaces the hash, deletes every session, and clears lockout:

```sh
go run ./cmd/server reset-admin
```

## Docker

The image is a static binary (`CGO_ENABLED=0`) on a pinned distroless nonroot base. The root filesystem is read-only, all capabilities are dropped, `no-new-privileges` is set, and `/tmp` is a tmpfs. The only writable application data is the `/data` volume. The Docker socket is not mounted. Nothing is published except `127.0.0.1` on the host.

```sh
cp .env.example .env
# edit PUBLIC_ORIGIN and the certificate paths
mkdir -p secrets
printf '%s\n' 'replace-this-password' > secrets/admin_password.txt
chmod 600 secrets/admin_password.txt
docker compose up -d --build
```

`docker compose down` stops the container and keeps the volume. `docker compose down -v` deletes the named volume, including ciphertext that has not expired yet.

Publishing `0.0.0.0:8443:8443` instead of `127.0.0.1` listens on every interface. Do that only behind a firewall that allows the proxy and nobody else.

The healthcheck runs `/pwpush healthcheck`. It does not open the database. In direct mode it trusts the PEMs in `TLS_CERT_FILE` and checks that `/healthz` returns `ok`.

## LAN testing with an IP address

Use an IP SAN, not a DNS name, when `PUBLIC_ORIGIN` is an address:

```sh
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout certs/tls.key -out certs/tls.crt \
  -subj /CN=192.168.1.20 \
  -addext subjectAltName=IP:192.168.1.20
```

```sh
PUBLIC_ORIGIN=https://192.168.1.20:8443
LISTEN_ADDR=192.168.1.20:8443
TLS_MODE=direct
```

The application will not invent this address from a network interface. If the machine's address changes, change `PUBLIC_ORIGIN` and the certificate. Browsers treat a raw IP as a separate origin, and some will not store HSTS for it.

## HTTPS with a self-signed development certificate

`TLS_MODE=direct` loads the certificate before it listens. Startup fails if the certificate is expired or the SAN does not equal the host in `PUBLIC_ORIGIN`. There is no automatic certificate generation. Trust the self-signed certificate in the administrator and recipient browsers, or use a name you already trust. HSTS is sent only in direct mode (`max-age=63072000; includeSubDomains`). Use a dedicated hostname so that policy does not surprise other sites.

## HTTPS with a corporate CA

Ask the corporate CA for a certificate whose SAN matches `PUBLIC_ORIGIN`. Put the leaf and the CA certificates that the healthcheck needs into `TLS_CERT_FILE`, and the key into `TLS_KEY_FILE`. No code change is required. The same files are mounted into the container by Compose.

## Future HAProxy

Keep this process in `TLS_MODE=proxy`. It listens on plain HTTP and does not send HSTS. HAProxy terminates TLS, sends HSTS, and adds the client address with `option forwardfor`.

`TRUSTED_PROXY_IPS` must list the address this process sees as the TCP peer. The client IP is the last item of the last `X-Forwarded-For` line. A missing or invalid last item uses the proxy's own address. Entries to the left are ignored. If the peer is not in the trusted list, the header is ignored.

Trusting the header is not enough. The listener must be reachable only from that proxy, by a firewall or a Docker network. The Compose file publishes `127.0.0.1` so a proxy on the same host can connect, and other machines cannot. Do not put HAProxy in this Compose file. It stays outside the application deployment.

Example backend stanza, with the application on loopback port 8443:

```
frontend https
    bind :443 ssl crt /etc/haproxy/certs/site.pem
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains"
    default_backend pwpush

backend pwpush
    option forwardfor
    server app 127.0.0.1:8443 check
```

Set `TRUSTED_PROXY_IPS` to the source address of those connections. When HAProxy is on the same host and talks to `127.0.0.1`, that address is `127.0.0.1`.

## Firewall

Direct mode needs the published TLS port reachable by the people who open links. Prefer binding it to loopback and reaching it through an SSH tunnel or a proxy you control.

Proxy mode needs the public TLS port on the proxy only. The application port should accept packets from the proxy and drop the rest.

`GET /healthz` returns `ok` and nothing else. Do not expose it beyond the host that runs the healthcheck.

## Backup and restore

Stop the process, or rely on SQLite's WAL, and copy the whole data directory: `pwpush.db`, `pwpush.db-wal`, and `pwpush.db-shm`.

```sh
sqlite3 data/pwpush.db "PRAGMA wal_checkpoint(TRUNCATE);"
tar -C data -cf pwpush-backup.tar pwpush.db
```

Restore by stopping the process, replacing the data directory, and starting again. A backup contains ciphertext, auth hashes, reservation rows, and the administrator hash. It can also still contain rows that the application has deleted, because a copy taken earlier is a copy. Keep backups for a short time, or do not keep them. The master key is not in the backup. The ciphertext is not useful without the fragment, and the fragment is not in the database.

## Secure deletion

On a successful reveal the row is deleted inside the same transaction that returns the ciphertext. Expired secrets and expired reservations are deleted by a background job. `secure_delete=ON` asks SQLite to overwrite freed pages.

That does not guarantee the bytes are gone from the disk. The WAL, checkpoints, backups, filesystem snapshots, and SSD wear-leveling can all retain old pages. Do not describe a `DELETE` as forensic erasure.

`docker compose down -v` deletes the Docker volume. It does not scrub the underlying storage.

## Security limitations

- The page the server sends is trusted. A modified script can read the fragment.
- The full URL, including `#`, is sensitive in browser history until `replaceState` runs, and the previous history entry can still hold it.
- Refreshing after the fragment is stripped does not burn the secret. A successful reveal that fails decryption does.
- Rate limits are per process and reset on restart. This deployment must not run more than one replica. `MaxOpenConns` is 1.
- Login lockout and the Argon2 semaphore can lock the administrator out. `reset-admin` clears both the lockout and the sessions.
- Logs omit URLs, bodies, ciphertext, keys, and full ids.
- Sessions store SHA-256 of a 256-bit token. The cookie is `__Host-session`, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, with no `Domain`. Idle time is 30 minutes. Absolute lifetime is 12 hours.
- Admin POSTs require `Origin` equal to `PUBLIC_ORIGIN` and a CSRF token. `Sec-Fetch-Site`, when present, must be `same-origin`. `same-site` is rejected.

## Tests

```sh
go test ./...
go vet ./...
staticcheck ./...
govulncheck ./...
node --test web/crypto.test.mjs
```

The Node test is the WebCrypto contract: HKDF split, AAD `v1|` plus the id, rejection of a mismatched AAD, rejection of a tampered ciphertext, and proof that the auth token is not an AES key. The Go server does not implement AES decryption.
