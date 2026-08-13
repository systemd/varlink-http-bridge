# varlink-httpd

This is an HTTP bridge to make local varlink services available
remotely. The main use case is systemd, so only the subset of varlink
that systemd needs is supported right now.

It takes a directory with varlink sockets (or symlinks to varlink
sockets) like `/run/varlink/registry` as the argument and will serve
whatever it finds in there. Sockets can be added or removed dynamically
in the dir as needed.

## URL Schema

```
POST /call/{method}                    → invoke method (c.f. varlink call, supports ?socket=)
GET  /sockets                          → list available sockets (c.f. valinkctl list-registry)
GET  /sockets/{socket}                 → socket info (c.f. varlinkctl info)
GET  /sockets/{socket}/{interface}     → interface details, including method names (c.f. varlinkctl list-methods)

GET  /health                           → health check
```

For `/call`, the socket is derived from the method name by stripping
the last `.Component` (e.g. `io.systemd.Hostname.Describe` connects
to socket `io.systemd.Hostname`). The `?socket=` query parameter
overrides this for cross-interface calls, e.g. to call
`io.systemd.service.SetLogLevel` on the `io.systemd.Hostname` socket.

For `/call` the parameters are POSTed as regular JSON.

### Websocket support

```
GET  /ws/sockets/{socket}              → transparent varlink-over-websocket proxy
```

The websocket endpoint is a transparent proxy that forwards raw bytes
between the websocket and the varlink unix socket in both directions.
Clients are expected to speak raw varlink wire protocol.

This makes the bridge compatible with libvarlink `varlink --bridge`
via `websocat --binary`, enabling full varlink features (including
`--more`) over the network.

## Default port

The default port is **1031** (NCC-1031, USS Discovery) - because every
bridge needs a ship, and this one discovers your varlink services.

## Examples (curl)

Using `curl` for direct calls is usually more convenient/ergonomic than
using the websocket endpoint.

For demo purposes, let's first start the service *without authentication*.
This mode is NOT SECURE! See below how to set up authentication.

```console
$ systemd-run --user ./target/debug/varlink-httpd --insecure

$ curl -s http://localhost:1031/sockets | jq
{
  "sockets": [
    "io.systemd.AskPassword",
    "io.systemd.BootControl",
    "io.systemd.Credentials",
    "io.systemd.FactoryReset",
    "io.systemd.Hostname",
    "io.systemd.Import",
    "io.systemd.Journal",
    "io.systemd.JournalAccess",
    "io.systemd.Login",
    "io.systemd.Machine",
    "io.systemd.MachineImage",
    "io.systemd.Manager",
    "io.systemd.MountFileSystem",
    "io.systemd.MuteConsole",
    "io.systemd.NamespaceResource",
    "io.systemd.Repart",
    "io.systemd.Resolve",
    "io.systemd.Resolve.Monitor",
    "io.systemd.Shutdown",
    "io.systemd.Udev",
    "io.systemd.Unit",
    "io.systemd.UserDatabase",
    "io.systemd.sysext"
  ]
}

$ curl -s http://localhost:1031/sockets/io.systemd.Hostname | jq
{
  "interfaces": [
    "io.systemd",
    "io.systemd.Hostname",
    "io.systemd.service",
    "org.varlink.service"
  ],
  "product": "systemd (systemd-hostnamed)",
  "url": "https://systemd.io/",
  "vendor": "The systemd Project",
  "version": "259 (259-1)"
}

$ curl -s http://localhost:1031/sockets/io.systemd.Hostname/io.systemd.Hostname | jq
{
  "method_names": [
    "Describe"
  ]
}

$ curl -s -X POST http://localhost:1031/call/io.systemd.Hostname.Describe -d '{}' -H "Content-Type: application/json" | jq .StaticHostname
"myhost"

$ curl -s -X POST http://localhost:1031/call/org.varlink.service.GetInfo?socket=io.systemd.Hostname -d '{}' -H "Content-Type: application/json" | jq
{
  "interfaces": [
    "io.systemd",
    "io.systemd.Hostname",
    "io.systemd.service",
    "org.varlink.service"
  ],
  "product": "systemd (systemd-hostnamed)",
  "url": "https://systemd.io/",
  "vendor": "The systemd Project",
  "version": "259 (259-1)"
}

# streaming methods use 'Accept: application/json-seq' (RFC 7464)
$ curl -s -H "Accept: application/json-seq" -H "Content-Type: application/json" \
    http://localhost:1031/call/io.systemd.UserDatabase.GetUserRecord \
    -d '{"service":"io.systemd.Multiplexer"}' | jq --seq
{
  "incomplete": true,
  "record": {
    "gid": 0,
    "homeDirectory": "/root",
    "realName": "Super User",
    "shell": "/bin/bash",
    ...
    "uid": 0,
    "userName": "root"
  }
}
...
```

## Examples (varlinkctl transparent bridge mode)

Systemd version v260+ supports pluggable protocols for varlink,
which allows the bridge to be used transparently.

Copy `varlinkctl-http` to `/usr/lib/systemd/varlink-bridges/http`
and link it as `/usr/lib/systemd/varlink-bridges/{https,ws,wss,vsock,vsock+tls}`.
This can be done automatically by `just install_client`.
Alternatively, `$SYSTEMD_VARLINK_BRIDGES_DIR` can be set if permanent installation is not desired.

```console
$ varlinkctl introspect http://localhost:1031/ws/sockets/io.systemd.Hostname
interface io.systemd
...

$ varlinkctl call http://localhost:1031/ws/sockets/io.systemd.Hostname io.systemd.Hostname.Describe {}
{
        "Hostname" : "myhost",
...
```

## Examples (websocket)

The examples use websocat because curl for websockets support is relatively new and
still a bit cumbersome to use.

```console
$ cargo install websocat
...

# call via websocat: note that this is the raw procotol so the result is wrapped in "parameters"
# note that the reply also contains the raw \0 so we filter them
$ printf '{"method":"io.systemd.Hostname.Describe","parameters":{}}\0' | \
    websocat ws://localhost:1031/ws/sockets/io.systemd.Hostname | tr -d '\0' | jq
{
  "parameters": {
    "Hostname": "myhost",
...

# io.systemd.Unit.List streams the output
$ printf '{"method":"io.systemd.Unit.List","parameters":{}, "more": true}\0' | \
    websocat  --no-close  ws://localhost:1031/ws/sockets/io.systemd.Manager | tr -d '\0' | jq
{
  "parameters": {
    "context": {
      "Type": "device",
...

# and user records come via "continues": true
$ printf '{"method":"io.systemd.UserDatabase.GetUserRecord", "parameters": {"service":"io.systemd.Multiplexer"}, "more": true}\0' | \
    websocat --no-close ws://localhost:1031/ws/sockets/io.systemd.UserDatabase | tr '\0' '\n' | jq
{
  "parameters": {
    "record": {
      "userName": "root",
      "uid": 0,
      "gid": 0,
...

# varlinkctl is supported via our varlinkctl-http
$ VARLINK_BRIDGE_URL=http://localhost:1031/ws/sockets/io.systemd.UserDatabase \
    varlinkctl call --more /usr/libexec/varlinkctl-http \
	io.systemd.UserDatabase.GetUserRecord '{"service":"io.systemd.Multiplexer"}'

# libvarlink bridge mode gives full varlink CLI support over the network
$ varlink --bridge "websocat --binary ws://localhost:1031/ws/sockets/io.systemd.Hostname" info
Vendor: The systemd Project
Product: systemd (systemd-hostnamed)
...

$ varlink --bridge "websocat --binary ws://localhost:1031/ws/sockets/io.systemd.Hostname" \
    call io.systemd.Hostname.Describe
{
  "Hostname": "myhost",
  "StaticHostname": "myhost",
  ...
}
```


## Systemd services

Two socket units are shipped, both backed by the same
`varlink-httpd.service`:

- `varlink-httpd.socket` listens on TCP `0.0.0.0:1031`.
- `varlink-httpd-vsock.socket` listens on `vsock::1031` and has
  `ConditionVirtualization=vm`, so it only activates inside a VM. On
  bare metal or the host it is silently skipped, which makes it safe
  to enable unconditionally.

Both sockets can be enabled at the same time.
If both are enabled, systemd passes two fds to the service on activation.
The daemon starts on demand when the first connection arrives
and listens on boths sockets, regardless of which connection came first.

The daemon binary and unit files can be installed with `just install_server`.

After installation, enable with:
```console
# systemctl enable --now varlink-httpd.socket varlink-httpd-vsock.socket
```

## Authentication

Since `varlink-httpd` runs as root, allows connections over the
network, exposes privileged information and allows arbitrary commands
to be invoked, authentication MUST be used.

Two modes of authenentication are supported:
TLS certificates and SSH key signatures.


### TLS / mTLS

TLS flag names follow the systemd convention.

```
--cert=PATH    path to TLS certificate PEM file
--key=PATH     path to TLS private key PEM file
--trust=PATH   path to CA certificate PEM for client verification (mTLS)
```

Providing `--trust=` implicitly enables mTLS: the server will
require clients to present a certificate signed by that CA.

#### systemd credentials

When running as a systemd service, the bridge discovers TLS material
from `$CREDENTIALS_DIRECTORY` (see `systemd.exec(5)`).  The credential
file names match the CLI flag names: `cert`, `key`, `trust`.

The shipped unit file (`varlink-httpd.service`) uses `ImportCredential=`
to import well-known credential names from the credstore and rename
them to the short names the service expects.  To provision TLS:

```console
# cp server.pem     /etc/credstore/varlink-httpd.tls.certificate
# systemd-creds encrypt server-key.pem /etc/credstore.encrypted/varlink-httpd.tls.key
# cp ca.pem         /etc/credstore/varlink-httpd.tls.trust
```

Explicit CLI flags take priority over credentials.

#### Client (varlinkctl-http)

The `varlinkctl-http` binary acts as a bridge between `varlinkctl`
and `varlink-httpd`, supporting TLS and mTLS. It looks for
client TLS material in the first existing directory:

* `$XDG_CONFIG_HOME/varlinkctl-http/`
* `~/.config/varlinkctl-http/`
* `/etc/varlinkctl-http/`

| File                   | Purpose                                   |
|------------------------|-------------------------------------------|
| `client-cert-file`     | Client certificate PEM (for mTLS)         |
| `client-key-file`      | Client private key PEM (for mTLS)         |
| `server-ca-file`       | CA certificate PEM (for private/self-signed server CAs) |

The system CAs are used automatically. For mTLS, drop the client cert
and key into the config directory:

```console
$ mkdir -p ~/.config/varlinkctl-http
$ cp client-cert.pem ~/.config/varlinkctl-http/client-cert-file
$ cp client-key.pem  ~/.config/varlinkctl-http/client-key-file
$ cp ca.pem          ~/.config/varlinkctl-http/server-ca-file

$ VARLINK_BRIDGE_URL=https://myhost:1031/ws/sockets/io.systemd.Hostname \
    varlinkctl call exec:/usr/libexec/varlinkctl-http \
    io.systemd.Hostname.Describe '{}'
```

### SSH key authentication

The bridge can authenticate requests using SSH public keys. If you
have an SSH agent running clients authenticate automatically with zero
extra configuration. Note that RSA keys are *not* supported, just
Ed25519 and ECDSA keys.

#### Server setup

The bridge discovers authorized keys automatically from these
locations (first match wins):

1. `--authorized-keys PATH` — explicit CLI flag
2. `/etc/varlink-httpd/authorized_keys` — config file
3. `$CREDENTIALS_DIRECTORY/ssh.authorized_keys.root` — systemd credential (see `systemd.exec(5)`)

The simplest setup is to pass the path explicitly:

```console
$ varlink-httpd --authorized-keys ~/.ssh/authorized_keys
```

To fetch keys from GitHub (or any HTTPS URL) and save them locally,
use the `import-ssh` subcommand:

```console
$ run0 varlink-httpd import-ssh gh:myuser
Wrote 3 key line(s) to /etc/varlink-httpd/authorized_keys, run with:
  varlink-httpd --authorized-keys /etc/varlink-httpd/authorized_keys
```

The source can be `gh:<user>` (shorthand for
`https://github.com/<user>.keys`) or any `https://` URL.  The output
path is auto-detected but can be overridden with a second positional
argument.  Once written to `/etc/varlink-httpd/authorized_keys`,
the bridge picks up the file automatically (discovery path 2) so the
`--authorized-keys` flag is no longer needed.

When running as a systemd service, the bridge discovers keys from
credentials automatically (discovery paths 3 and 4):

```ini
[Service]
LoadCredential=ssh.authorized_keys.root:/root/.ssh/authorized_keys
```

#### Client setup (key selection)

The varlinkctl-http uses two methods for signing, checked in order:

1. **`VARLINK_SSH_KEY`** — If the private key is passed it will read
   the private key file directly. If the public key is passed it will
   look for the corresponding private key in the ssh agent.

   ```console
   $ export VARLINK_SSH_KEY=~/.ssh/id_ed25519
   ```

2. **`SSH_AUTH_SOCK`** — fall back to the SSH agent, using the first
   Ed25519 or ECDSA key it finds. No setup required when the agent is
   running.

Using `VARLINK_SSH_KEY` is useful in environments without an SSH agent
(e.g. systemd services, containers, CI):

```ini
[Service]
Environment=VARLINK_SSH_KEY=/my/private/bridge_key
```

#### Combining with TLS

SSH key auth and TLS/mTLS are independent and should be combined. For
example, use regular TLS (not mTLS) for transport encryption and SSH
keys for user authentication:

```console
$ varlink-httpd \
    --cert=server.pem \
    --key=server-key.pem \
    --authorized-keys ~/.ssh/authorized_keys
```

This is recommended because for websocket requests only the initial
"upgrade" request is signed with the ssh key, after the upgrade it is
a plain WebSocket which relies on the underlying TLS for security.

### JWT bearer authentication

The bridge can also authenticate requests with a JSON Web Token (JWT)
presented as `Authorization: Bearer <token>`. This is vendor-neutral:
any OIDC-style issuer that signs tokens with **RS256** or **ES256** and
publishes a JWKS works, including issuers you do not operate (GitHub
Actions, Google, Keycloak, Auth0, ...).

The node verifies the token's signature against the issuer's public keys
(its JWKS), then checks `iss`, `aud` and `exp`. Because `aud` from a
third-party IdP is often a shared value (not "this node"), real
authorization comes from **claim requirements** on the node: one or more
`--require-claim NAME=VALUE` rules that must all hold (see below).

> **TLS is required in production.** A bearer token has no
> proof-of-possession, so a captured token is replayable until it
> expires; only transport TLS protects it in flight.

#### Authorization: `--require-claim`

Each `--require-claim NAME=VALUE` requires claim `NAME` to be present and
to match `VALUE`. The rules compose:

- distinct names are **ANDed**: every named claim must match;
- repeating a name **ORs** its values: list it twice to allow either;
- `VALUE` is an exact match or a `*` wildcard (e.g. `repo:myorg/*`); array
  claims match if any element matches; `email_verified=true` works as-is.

At least one rule is required. Without any, a valid token from the issuer would
be accepted on `iss`/`aud`/`exp` alone, which is too weak for a third-party IdP
(its `aud` is shared, not per-caller). So if no rule is configured, JWT auth is
**not enabled**: the bridge logs a warning and leaves it off, while the other
authenticators (SSH, mTLS) keep working.

#### The issuer's public keys (JWKS)

The node needs the issuer's public keys to verify signatures. By default it
discovers them automatically: given an HTTPS `--issuer`, it fetches
`<issuer>/.well-known/openid-configuration`, follows the `jwks_uri`, and caches
the result. When a token arrives with an unknown key id the JWKS is re-fetched
on demand (rate-limited), so issuer key rotation is handled without a restart.
This is the right mode for third-party IdPs like Google and GitHub, which
rotate their keys.

To pin the keys instead (a self-run signer, an air-gapped node, or to avoid the
outbound fetch), point `--issuer-jwks` at a local JWKS file; it overrides
discovery and is hot-reloaded on change:

```console
$ curl -s https://<issuer>/.well-known/openid-configuration | jq -r .jwks_uri
https://<issuer>/.well-known/jwks
$ curl -s https://<issuer>/.well-known/jwks -o /etc/varlink-httpd/issuer-jwks.json
```

Server flags:

```
--issuer=URL                accepted 'iss' claim
--audience=ID               accepted 'aud' claim (default: hostname)
--issuer-jwks=PATH          pin a JWKS file (else fetched via OIDC discovery)
--require-claim=NAME=VALUE  require claim NAME to match VALUE (repeatable)
```

Any of these can also come from a systemd credential instead of a flag.
See "Auto-deploy via systemd credentials" below.

#### Working example: a GitHub Actions org

GitHub hands every workflow a short-lived OIDC token, so any CI job in
your org can drive the bridge with no client certificate and no custom
issuer. The token's GitHub claims (`repository_owner`, `repository`,
`sub`, ...) drive authorization; see [GitHub's OIDC token
reference](https://docs.github.com/en/actions/concepts/security/openid-connect#understanding-the-oidc-token)
for the full set of claims and their formats.

**Server**: trust the GitHub issuer and allow any repository in the
`myorg` organisation:

```console
$ varlink-httpd \
    --cert=server.pem --key=server-key.pem \
    --issuer=https://token.actions.githubusercontent.com \
    --audience=varlink-node-1 \
    --require-claim=repository_owner=myorg
```

The node discovers GitHub's keys over HTTPS; no JWKS file is needed.

`varlink-node-1` is a name you pick for this node: the server's `--audience` and
the workflow's `&audience=` (below) must use the same string. For GitHub the
audience is **not** an authorization boundary (the workflow chooses its own, so
any repo could request `varlink-node-1`); it only marks a token as minted for
this node. The `--require-claim` rules are what actually authorize, since GitHub,
not the caller, sets `repository_owner` / `repository` / `sub`.

Tighten the scope by adding or replacing `--require-claim` rules in the server
command above (they compose):

```console
# a single repo
--require-claim=repository=myorg/myrepo
# only the main branch of that repo (sub encodes the ref/event)
--require-claim="sub=repo:myorg/myrepo:ref:refs/heads/main"
# either of two repos (OR), and only from the prod environment (AND)
--require-claim=repository=myorg/a --require-claim=repository=myorg/b \
    --require-claim=environment=prod
```

**Client**: in the workflow, request a token for that audience and pass
it via `VARLINK_JWT` (requires `permissions: id-token: write`):

```yaml
jobs:
  drive-node:
    permissions:
      id-token: write           # allow minting the OIDC token
    runs-on: ubuntu-latest
    steps:
      - run: |
          # fetch the OIDC token for our node's audience
          TOKEN=$(curl -s \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=varlink-node-1" \
            -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            | jq -r .value)

          VARLINK_JWT="$TOKEN" \
          VARLINK_BRIDGE_URL=https://node-1:1031/ws/sockets/io.systemd.Hostname \
            varlinkctl call exec:/usr/libexec/varlinkctl-http \
            io.systemd.Hostname.Describe '{}'
```

#### Working example: a self-hosted Keycloak

For real logins (SSO, multiple users, central revocation) without depending on a
third party, run your own [Keycloak](https://www.keycloak.org/). Create a realm
and a `varlink` client (public, with *Direct access grants*); Keycloak then
serves discovery at `https://kc.example.com/realms/myrealm/.well-known/openid-configuration`,
so the node fetches the keys itself (no `--issuer-jwks`):

```console
$ varlink-httpd ... \
    --issuer=https://kc.example.com/realms/myrealm \
    --audience=varlink \
    --require-claim=sub=3f2a8c1e-...
```

`sub` is Keycloak's immutable per-user id (read it from the token, or the admin
UI), so the rule survives a username rename; `preferred_username=me` is the
readable alternative if you accept that a login name can change. Unlike the
GitHub and Google cases, the id token's `aud` is your own client id, so
`--audience=varlink` is a genuine boundary on top of the user claim. Fetch a
token with the password grant in one request (`curl -d grant_type=password -d
client_id=varlink -d scope="openid email" -d username=me -d password=... .../token`,
read `.id_token`); the device and authorization-code flows work too.

#### Other issuers (e.g. a personal Google account)

Any OIDC issuer that signs with RS256/ES256 and publishes a discovery document
works the same way: set `--issuer` and one or more `--require-claim` rules. A
personal Google account is tempting because everyone already has one, but mind
the audience. The easy path, `gcloud auth print-identity-token`, stamps `aud`
with the *shared* Google Cloud SDK client id
(`32555940559.apps.googleusercontent.com`) that every gcloud user also gets, so
`aud` is worthless as a boundary and a single rule on the verified `email` (or
`sub`) is the *only* thing authorizing the caller:

```console
$ varlink-httpd ... \
    --issuer=https://accounts.google.com \
    --audience=32555940559.apps.googleusercontent.com \
    --require-claim=email=you@gmail.com \
    --require-claim=email_verified=true
```

That works, but it leans the whole boundary on one claim, so do not loosen the
`email`/`sub` rule. To get a real `aud` back, register your own Google OAuth
client and fetch tokens with the device flow; by then you have done about as
much setup as standing up a dedicated issuer like the Keycloak above.

#### Auto-deploy via systemd credentials

Every JWT setting can come from a systemd credential instead of a flag,
so a node can be provisioned entirely from the credstore (see
`systemd.exec(5)` and `systemd.system-credentials(7)`). JWT auth turns on
as soon as an issuer is configured by either route.

| Credential                         | Equivalent flag  |
|------------------------------------|------------------|
| `varlink-httpd.jwt.issuer`         | `--issuer`       |
| `varlink-httpd.jwt.audience`       | `--audience`     |
| `varlink-httpd.jwt.jwks`           | `--issuer-jwks` (optional; omit to use OIDC discovery) |
| `varlink-httpd.jwt.require-claims` | `--require-claim` (one `NAME=VALUE` per line; `#` comments allowed) |

For the GitHub org example above, provision the credstore instead of flags. With
discovery there is no JWKS to ship, so the issuer is the only key-related entry:

```console
# /etc/credstore/ entries (or LoadCredential=/ImportCredential= in the unit)
$ echo https://token.actions.githubusercontent.com \
    > /etc/credstore/varlink-httpd.jwt.issuer
$ echo varlink-node-1 > /etc/credstore/varlink-httpd.jwt.audience
$ echo repository_owner=myorg > /etc/credstore/varlink-httpd.jwt.require-claims
```

## vsock transport

The bridge supports `AF_VSOCK` as an alternative to TCP, allowing
host-to-guest communication without a network. vsock traffic cannot
be sniffed on the network, but any process on the host can connect
to a guest's vsock port, so authentication is still recommended
(mTLS, SSH key auth, or both).

### SSH key auth over vsock

vsock with SSH key auth works without TLS — the transport is not
sniffable so the lack of encryption is acceptable:

```console
# Server (inside the guest):
$ varlink-httpd --bind=vsock --authorized-keys ~/.ssh/authorized_keys

# Client (on the host):
$ varlinkctl call vsock://3/ws/sockets/io.systemd.Hostname \
    io.systemd.Hostname.Describe '{}'
```

(If this fails with a "Protocol not supported" error, the `vsock`
helper is not installed properly in `/usr/lib/systemd/varlink-bridges/`.
See the installation instructions above.)

### mTLS over vsock

Server (inside the guest):

```console
$ varlink-httpd --bind=vsock \
    --cert=server.pem --key=server-key.pem --trust=ca.pem
```

Client (on the host), using `vsock+tls://`:

```console
$ varlinkctl call vsock+tls://3/ws/sockets/io.systemd.Hostname \
    io.systemd.Hostname.Describe '{}'
```

The client looks for its certificate and key in the same config
directories as for TCP (see [Client (varlinkctl-http)](#client-varlinkctl-http)
below). CID 3+ are guests; CID 2 is the host.
