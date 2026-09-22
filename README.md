# varlink-httpd

This is an HTTP bridge to make local varlink services available
remotely. The main use case is systemd, so only the subset of varlink
that systemd needs is supported right now.

It takes a directory with varlink sockets (or symlinks to varlink
sockets) like `/run/varlink/registry` as the argument and will serve
whatever it finds in there. Sockets can be added or removed dynamically
in the dir as needed.

See [README.relayd.md](README.relayd.md) for the plan to reach a
`varlink-httpd` behind NAT or a firewall through a relay.

## URL Schema

```
POST /call/{method}                    → invoke method (c.f. varlink call, supports ?service=)
POST /call/{service}/{method}          → invoke method on an explicitly given service
GET  /services                         → list available services (c.f. valinkctl list-registry)
GET  /services/{service}               → service info (c.f. varlinkctl info)
GET  /services/{service}/{interface}   → documented method, type and error names (c.f. varlinkctl list-methods)
GET  /idl/{service}/{interface}        → the varlink IDL itself (c.f. varlinkctl introspect)
GET  /openapi/{service}/{interface}    → OpenAPI 3.1 description generated from varlink IDL
                                         (bridge-specific extension, not part of the spec)

GET  /health                           → health check
```

For `/call/{method}`, the service is derived from the method name by
stripping the last `.Component` (e.g. `io.systemd.Hostname.Describe`
connects to service `io.systemd.Hostname`). The `?service=` query
parameter overrides this for cross-interface calls, e.g. to call
`io.systemd.service.SetLogLevel` on the `io.systemd.Hostname` service.
The `/call/{service}/{method}` form makes the service explicit instead;
this is the form the generated OpenAPI descriptions use.

For `/call` the parameters are POSTed as regular JSON; an empty body is
accepted as `{}`.

Streaming methods (the varlink `more` flag) are selected with the
`?more=true` query parameter and reply with an RFC 7464 JSON text
sequence, content type `application/json-seq`.
`more` changes what the call does, so it is a call parameter rather than
content negotiation: the `Accept` header is not consulted.

### Websocket support

```
GET  /ws/services/{service}            → transparent varlink-over-websocket bridge
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
using the websocket endpoint. The examples use `--json`, which needs
curl 7.82 or newer; older versions take
`-X POST -H "Content-Type: application/json" -d ...` instead.

For demo purposes, let's first start the service *without authentication*.
This mode is NOT SECURE! See below how to set up authentication.
`--insecure` also turns TLS off, hence the plain `http://` below.

```console
$ systemd-run --user ./target/debug/varlink-httpd --insecure

$ curl -s http://localhost:1031/services | jq
{
  "services": [
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

$ curl -s http://localhost:1031/services/io.systemd.Hostname | jq
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

$ curl -s http://localhost:1031/services/io.systemd.Hostname/io.systemd.Hostname | jq
{
  "methods": [
    {
      "name": "Describe",
      "description": "Returns hostname, kernel, OS, hardware, firmware and other machine metadata in one call."
    }
  ],
  "types": [],
  "errors": [],
  "idl": "/idl/io.systemd.Hostname/io.systemd.Hostname",
  "openapi": "/openapi/io.systemd.Hostname/io.systemd.Hostname"
}

$ curl -s http://localhost:1031/call/io.systemd.Hostname.Describe --json '{}' | jq .StaticHostname
"myhost"

$ curl -s 'http://localhost:1031/call/org.varlink.service.GetInfo?service=io.systemd.Hostname' --json '{}' | jq
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

# '?oneway=true' sets the varlink 'oneway' flag for fire-and-forget calls.
# The bridge answers '204 No Content' once the call is written to the
# service; only a failure to reach the service is still reported (as 502)
$ curl -s -o /dev/null -w '%{http_code}\n' \
    'http://localhost:1031/call/io.systemd.Journal.Synchronize?oneway=true' --json '{}'
204

# streaming methods (varlink "more" flag) are requested with ?more=true;
# the replies come back as a json-seq (RFC 7464).
$ curl -s 'http://localhost:1031/call/io.systemd.UserDatabase.GetUserRecord?more=true' \
    -H 'Accept: application/json-seq' \
    --json '{"service":"io.systemd.Multiplexer"}' | jq --seq
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
$ varlinkctl introspect http://localhost:1031/ws/services/io.systemd.Hostname
interface io.systemd
...

$ varlinkctl call http://localhost:1031/ws/services/io.systemd.Hostname io.systemd.Hostname.Describe {}
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
    websocat ws://localhost:1031/ws/services/io.systemd.Hostname | tr -d '\0' | jq
{
  "parameters": {
    "Hostname": "myhost",
...

# io.systemd.Unit.List streams the output
$ printf '{"method":"io.systemd.Unit.List","parameters":{}, "more": true}\0' | \
    websocat  --no-close  ws://localhost:1031/ws/services/io.systemd.Manager | tr -d '\0' | jq
{
  "parameters": {
    "context": {
      "Type": "device",
...

# and user records come via "continues": true
$ printf '{"method":"io.systemd.UserDatabase.GetUserRecord", "parameters": {"service":"io.systemd.Multiplexer"}, "more": true}\0' | \
    websocat --no-close ws://localhost:1031/ws/services/io.systemd.UserDatabase | tr '\0' '\n' | jq
{
  "parameters": {
    "record": {
      "userName": "root",
      "uid": 0,
      "gid": 0,
...

# varlinkctl is supported via our varlinkctl-http
$ VARLINK_BRIDGE_URL=http://localhost:1031/ws/services/io.systemd.UserDatabase \
    varlinkctl call --more /usr/libexec/varlinkctl-http \
	io.systemd.UserDatabase.GetUserRecord '{"service":"io.systemd.Multiplexer"}'

# libvarlink bridge mode gives full varlink CLI support over the network
$ varlink --bridge "websocat --binary ws://localhost:1031/ws/services/io.systemd.Hostname" info
Vendor: The systemd Project
Product: systemd (systemd-hostnamed)
...

$ varlink --bridge "websocat --binary ws://localhost:1031/ws/services/io.systemd.Hostname" \
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

Authentication has two orthogonal layers that compose:

```
--auth=MECHANISMS   per-request authentication to enable (required)
```

`--auth=ssh` authenticates every request by an SSH key signature.
`--auth=none` selects no per-request mechanism, leaving mTLS to
authenticate the client; without mTLS the bridge refuses to start.

mTLS is enabled separately (see below) and applies on top of whatever
`--auth=` selects, so `--auth=ssh` together with mTLS requires both to
pass. `--insecure` is the one way to serve with no authentication at
all, and implies `--auth=none`.

### TLS / mTLS

TLS flag names follow the systemd convention.

```
--cert=PATH    path to TLS certificate PEM file
--key=PATH     path to TLS private key PEM file
--trust=PATH   path to CA certificate PEM for client verification (mTLS)
--require-mtls require a verified client certificate
--insecure     run over plain HTTP without any authentication (DANGEROUS)
```

`--require-mtls` makes every client present a certificate signed by the
configured CA. `--trust=` implies it, since a CA is only ever used to
verify clients.

Pass `--require-mtls` on its own when the CA arrives as a credential
rather than a file, which systemd may only provide on a later
`systemctl reload`. Until a CA is available every client is rejected.
A `trust` credential without `--require-mtls` won't enable mTLS.

Listeners always speak TLS unless `--insecure` is given. Without
`--cert=`/`--key=` the bridge generates a self-signed certificate on
first start, persists it under `$STATE_DIRECTORY`
(`/var/lib/varlink-httpd` for the shipped unit) and prints the key to
pin, e.g. `sha256//N/XBoWQvWrJScutg5/l0WO5sC1/QV2th677ylUNaVa8=`. The
pin covers the public key, not the certificate, so regenerating the
certificate from the same key keeps existing pins valid. Clients take it
via `known-hosts` (see below) or `curl --pinnedpubkey`.

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

The `trust` credential only takes effect together with `--require-mtls`,
so add it to the unit with a drop-in:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/varlink-httpd --auth=ssh --require-mtls
```

Explicit CLI flags take priority over credentials.

The CA is re-read when it changes (checked on each handshake), so a
rotated CA, or one that only appears on a later `systemctl reload`,
takes effect without a restart. Removing it rejects every client again
rather than falling back to accepting them. As with SSH keys, systemd
refreshes credentials on reload only with systemd >= 260
(`RefreshOnReload=`); on older versions a restart is needed.

The server's own certificate and key are read once at start, so
replacing those does still require a restart.

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
| `known-hosts`          | pinned server public keys, one line per peer |
| `api-key`              | API key, for `--auth=api-key` servers; refused if world-readable |

Without a `server-ca-file` the system CAs are used. If present, it
is the exclusive trust anchor and system CAs are no longer consulted.

A certificate that validates against the configured CA is accepted as-is;
a self-signed one is pinned in `known-hosts` instead, learned on first
contact and refused if it later changes. The peer is `host:port`, or
`vsock:CID:PORT` for vsock. For mTLS, drop the client cert
and key into the config directory:

```console
$ mkdir -p ~/.config/varlinkctl-http
$ cp client-cert.pem ~/.config/varlinkctl-http/client-cert-file
$ cp client-key.pem  ~/.config/varlinkctl-http/client-key-file
$ cp ca.pem          ~/.config/varlinkctl-http/server-ca-file

$ VARLINK_BRIDGE_URL=https://myhost:1031/ws/services/io.systemd.Hostname \
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
locations:

1. `--authorized-keys PATH` — explicit CLI flag; when given it is the only
   source used
2. `/etc/varlink-httpd/authorized_keys` — config file
3. `$CREDENTIALS_DIRECTORY/ssh.authorized_keys.root` and
   `ssh.ephemeral-authorized_keys-all` — systemd credentials (see
   `systemd.exec(5)`)
4. `$CREDENTIALS_DIRECTORY/varlink-httpd.ssh.authorized-keys.*` — additional
   credentials, imported by the unit using a glob. Each provider (a
   generated node config, a local admin, a confext) ships its own
   `/etc/credstore/varlink-httpd.ssh.authorized-keys.<provider>` rather than
   overwriting a shared file, which neither the credstore nor overlaid
   confexts can merge.

Keys from 2, 3 and 4 are merged and deduplicated.

All sources are re-read when they change (checked lazily on each
request), so key updates need no restart. Note that systemd imports
credentials only at service start: updating credential-sourced keys
requires a `systemctl reload varlink-httpd` to refresh the imported
credentials, which needs systemd >= 260 (`RefreshOnReload=`). On older
systemd the setting is ignored and a full restart is needed instead.

The simplest setup is to pass the path explicitly:

```console
$ varlink-httpd --auth=ssh --authorized-keys ~/.ssh/authorized_keys
```

To fetch keys from GitHub (or any HTTPS URL) and save them locally,
use the `import-ssh` subcommand:

```console
$ run0 varlink-httpd import-ssh gh:myuser
Wrote 3 key(s) to /etc/varlink-httpd/authorized_keys, run with:
  varlink-httpd --auth=ssh --authorized-keys=/etc/varlink-httpd/authorized_keys
```

The source can be `gh:<user>` (shorthand for
`https://github.com/<user>.keys`) or any `https://` URL.  The output
path is auto-detected but can be overridden with a second positional
argument.  Once written to `/etc/varlink-httpd/authorized_keys`,
the bridge picks up the file automatically (discovery path 2) so the
`--authorized-keys` flag is no longer needed; `--auth=ssh` still is.

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
$ varlink-httpd --auth=ssh \
    --cert=server.pem \
    --key=server-key.pem \
    --authorized-keys ~/.ssh/authorized_keys
```

This is recommended because for websocket requests only the initial
"upgrade" request is signed with the ssh key, after the upgrade it is
a plain WebSocket which relies on the underlying TLS for security.

The signed token covers the HTTP method, the path including the query
string, the `Accept` header, a per-request nonce and the TLS channel
binding. The request body is not signed, its integrity
relies on TLS.


## vsock transport

The bridge supports `AF_VSOCK` as an alternative to TCP, allowing
host-to-guest communication without a network. vsock traffic cannot
be sniffed on the network, but any process on the host can connect
to a guest's vsock port, so authentication is still recommended
(mTLS, SSH key auth, or both).

### SSH key auth over vsock

vsock needs no CA: the guest serves its generated self-signed
certificate and the host pins it on first contact, so SSH keys are the
only material to provision. Plain `vsock://` speaks no TLS and reaches
only an `--insecure` server.

```console
# Server (inside the guest):
$ varlink-httpd --auth=ssh --bind=vsock --authorized-keys ~/.ssh/authorized_keys

# Client (on the host):
$ varlinkctl call vsock+tls://3/ws/services/io.systemd.Hostname \
    io.systemd.Hostname.Describe '{}'
```

(If this fails with a "Protocol not supported" error, the `vsock`
helper is not installed properly in `/usr/lib/systemd/varlink-bridges/`.
See the installation instructions above.)

### mTLS over vsock

Server (inside the guest):

```console
$ varlink-httpd --auth=none --bind=vsock \
    --cert=server.pem --key=server-key.pem --trust=ca.pem
```

Client (on the host), using `vsock+tls://`:

```console
$ varlinkctl call vsock+tls://3/ws/services/io.systemd.Hostname \
    io.systemd.Hostname.Describe '{}'
```

The client looks for its certificate and key in the same config
directories as for TCP (see [Client (varlinkctl-http)](#client-varlinkctl-http)
below). CID 3+ are guests; CID 2 is the host.

## API key authentication

For plain `curl` (shell scripts, cron jobs, CI) the bridge supports
static API keys presented as `Authorization: Bearer <key>`. The
server only stores the SHA-256 hash of each key. Enable it with
`--auth=api-key`; it can be combined with SSH key auth as
`--auth=api-key,ssh`, mechanisms are tried in the given order and the
first one that accepts wins.

> **Keys must be random secrets, not passwords.** The stored hash is
> an unsalted SHA-256, which only protects a key with enough entropy;
> a hashed password is cracked in seconds. Use `gen-api-key` or a
> random generator such as `openssl rand -hex 32`. The bridge refuses
> keys shorter than 32 characters.

> **TLS is required in production.** An API key has no
> proof-of-possession: anyone who captures it can replay it. Only
> transport TLS (or a non-sniffable transport like vsock) protects it
> in flight. For stronger per-request authentication use SSH key auth.

### Server setup

Generate a key with the `gen-api-key` subcommand; it prints the key
to stdout exactly once and appends its hash to the API keys file:

```console
$ run0 varlink-httpd gen-api-key --name=deploy-script
vhb_9f8e7d6c5b4a...
Appended hash of API key 'deploy-script' to /etc/varlink-httpd/api-keys, run with:
  varlink-httpd --auth=api-key
```

With `--auth=api-key` the bridge reads API key hashes from these
locations:

1. `--api-keys=PATH` - explicit CLI flag; when given, it is the only
   file used
2. `varlink-httpd/api-keys` in the config hierarchy - `/etc` over `/run`
   over `/usr/lib`, and only the highest-precedence one is read, so a
   file in `/etc` shadows a vendor default in `/usr/lib`
3. the `varlink-httpd.api-keys` credential and every
   `varlink-httpd.api-keys.*` one - the shipped unit imports both from
   the credstore (see `systemd.exec(5)`), so each provider can drop its
   own file instead of editing a shared one

Keys from 2 and 3 are merged, so a credential adds to the config file
rather than replacing it. Credentials are re-enumerated on `systemctl
reload`, which is when `RefreshOnReload=credentials` swaps in a fresh
credentials tree.

The API keys file has one key per line, `sha256:<hex> [name]`, with
`#` comments allowed. The name identifies the key in logs; revoke a
key by deleting its line (the file is hot-reloaded, no restart
needed). To add a key generated elsewhere by hand, it must be at
least 32 random characters:

```console
$ API_KEY=$(openssl rand -hex 32)
$ echo "sha256:$(printf %s "${API_KEY:?}" | sha256sum | cut -d' ' -f1) ci-runner" \
    >> /etc/varlink-httpd/api-keys
```

### Using it with curl

`gen-api-key` registers the hash on the machine it runs on, so run it
on the server; only the printed key is copied to the client:

```console
myhost$ run0 varlink-httpd gen-api-key --name=laptop-cli
vhb_2048f47eb397b0eed671280444b6f89692170d9ae33a94713681d1a22ea0dc55
Appended hash of API key 'laptop-cli' to /etc/varlink-httpd/api-keys, run with:
  varlink-httpd --auth=api-key
```

Then, from anywhere that can reach the bridge. The bridge serves TLS
with a generated self-signed certificate unless `--cert=`/`--key=` are
given, so the client has to pin the key the server printed on first
start. curl checks `--pinnedpubkey` independently of the certificate
chain, so `-k` is still needed to accept the self-signed certificate;
the pin is what actually authenticates the server. With a certificate
from a real CA drop `-k` and `--pinnedpubkey` (or replace the latter
with `--cacert`):

```console
$ export API_KEY=vhb_2048f47eb397b0ee...   # the value printed above
$ export PIN=sha256//N/XBoWQvWrJScutg5/l0WO5sC1/QV2th677ylUNaVa8=   # printed by the server

$ curl -sk --pinnedpubkey "$PIN" -H "Authorization: Bearer $API_KEY" \
    https://myhost:1031/services | jq
{
  "services": [
    "io.systemd.Hostname",
...

$ curl -sk --pinnedpubkey "$PIN" -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -X POST https://myhost:1031/call/io.systemd.Hostname.Describe -d '{}' \
    | jq .StaticHostname
"top"
```

### Client (varlinkctl-http)

The `varlinkctl-http` bridge helper takes the key from `VARLINK_API_KEY`,
or from an `api-key` file in its config directory
(`~/.config/varlinkctl-http/` and friends, as for the client TLS
material); the environment wins, so a one-off key can override the
configured one. Either way API key auth takes priority over SSH key
auth:

```console
$ VARLINK_API_KEY="$API_KEY" \
  VARLINK_BRIDGE_URL=https://myhost:1031/ws/services/io.systemd.Hostname \
    varlinkctl call exec:/usr/libexec/varlinkctl-http \
    io.systemd.Hostname.Describe '{}'
```

### Provisioning via systemd credentials

Instead of a file in `/etc`, ship the hashes through the credstore;
the shipped unit imports `varlink-httpd.api-keys` automatically and
warns when it is present but `--auth=api-key` is not enabled (add it
to `ExecStart=` with a drop-in).
Because the file only contains hashes it can also be generated on one
machine and copied to the nodes as part of provisioning:

```console
$ varlink-httpd gen-api-key --name=deploy-script api-keys
vhb_9f8e7d6c5b4a...
$ scp api-keys myhost:/etc/credstore/varlink-httpd.api-keys
```
