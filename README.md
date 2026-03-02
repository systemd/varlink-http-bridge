# varlink-httpd

This is a http bridge to make local varlink services available via
http. The main use case is systemd, so only the subset of varlink that
systemd needs is supported right now.

It takes a directory with varlink sockets (or symlinks to varlink
sockets) like /run/varlink/registry as the argument and will serve
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

This makes the bridge compatible with libvarlink `varlink --brige`
via `websocat --binary`, enabling full varlink features (including
`--more`) over the network.

## Default port

The default port is **1031** (NCC-1031, USS Discovery) - because every
bridge needs a ship, and this one discovers your varlink services.

## Examples (curl)

Using curl for direct calls is usually more convenient/ergonimic than
using the websocket endpoint.

```console
$ systemd-run --user ./target/debug/varlink-httpd

$ curl -s http://localhost:1031/sockets | jq
{
  "sockets": [
    "io.systemd.Login",
    "io.systemd.Hostname",
    "io.systemd.sysext",
    "io.systemd.BootControl",
    "io.systemd.Import",
    "io.systemd.Repart",
    "io.systemd.MuteConsole",
    "io.systemd.FactoryReset",
    "io.systemd.Credentials",
    "io.systemd.AskPassword",
    "io.systemd.Manager",
    "io.systemd.ManagedOOM"
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
"top"

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

```

### Example (varlinkctl transparent bridge mode)

Systemd version v260+ supports pluggable protocols for varlink, with that the bridge
becomes even nicer.

```console
# copy varlinkctl-http into /usr/lib/systemd/varlink-bridges/http
# (or use SYSTEMD_VARLINK_BRIDGES_DIR)
$ varlinkctl introspect http://localhost:1031/ws/sockets/io.systemd.Hostname
interface io.systemd
...

$ varlinkctl call http://localhost:1031/ws/sockets/io.systemd.Hostname io.systemd.Hostname.Describe {}
{
        "Hostname" : "top",
...
```

### Examples (websocket)

The examples use websocat because curl for websockets support is relatively new and
still a bit cumbersome to use.

```console
$ cargo install websocat
...

# call via websocat: note that this is the raw procotol so the result is wrapped in "parameters"
# note that the reply also contains the raw \0 so we filter them
$ printf '{"method":"io.systemd.Hostname.Describe","parameters":{}}\0' | websocat ws://localhost:1031/ws/sockets/io.systemd.Hostname | tr -d '\0' | jq
{
  "parameters": {
    "Hostname": "top",
...

# io.systemd.Unit.List streams the output
$ printf '{"method":"io.systemd.Unit.List","parameters":{}, "more": true}\0' | websocat  --no-close  ws://localhost:1031/ws/sockets/io.systemd.Manager| tr -d '\0' | jq
{
  "parameters": {
    "context": {
      "Type": "device",
...

# and user records come via "continues": true
$ printf '{"method":"io.systemd.UserDatabase.GetUserRecord", "parameters": {"service":"io.systemd.Multiplexer"}, "more": true}\0' | websocat --no-close ws://localhost:1031/ws/sockets/io.systemd.Multiplexer | tr '\0' '\n'|jq
{
  "parameters": {
    "record": {
      "userName": "root",
      "uid": 0,
      "gid": 0,
...

# varlinkctl is supported via our varlinkctl-http
$ VARLINK_BRIDGE_URL=http://localhost:1031/ws/sockets/io.systemd.Multiplexer \
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
  "Hostname": "top",
  "StaticHostname": "top",
  ...
}

```

## TLS / mTLS

TLS flag names follow the systemd convention.

```
--cert=PATH    path to TLS certificate PEM file
--key=PATH     path to TLS private key PEM file
--trust=PATH   path to CA certificate PEM for client verification (mTLS)
```

Providing `--trust=` implicitly enables mTLS: the server will
require clients to present a certificate signed by that CA.

### systemd credentials

When running as a systemd service, the bridge automatically discovers
TLS material from `$CREDENTIALS_DIRECTORY` (see `systemd.exec(5)`).
The credential file names match the CLI flag names:

```ini
[Service]
LoadCredential=cert:/etc/ssl/certs/bridge.pem
LoadCredential=key:/etc/ssl/private/bridge.pem
LoadCredential=trust:/etc/ssl/ca/client-ca.pem
```

Explicit CLI flags take priority over credentials directory files.

### Client (varlinkctl-http)

The `varlinkctl-http` binary acts as a bridge between `varlinkctl`
and `varlink-httpd`, supporting TLS and mTLS. It looks for
client credentials in the first existing directory:

* `$XDG_CONFIG_HOME/varlink-httpd/`
* `~/.config/varlink-httpd/`
* `$CREDENTIALS_DIRECTORY`

The credential file names are:

| File                   | Purpose                                   |
|------------------------|-------------------------------------------|
| `client-cert-file`     | Client certificate PEM (for mTLS)         |
| `client-key-file`      | Client private key PEM (for mTLS)         |
| `server-ca-file`       | CA certificate PEM (for private/self-signed server CAs) |

The system CAs are used automatically. For mTLS, drop the client cert
and key into the config directory:

```console
$ mkdir -p ~/.config/varlink-httpd
$ cp client-cert.pem ~/.config/varlink-httpd/client-cert-file
$ cp client-key.pem  ~/.config/varlink-httpd/client-key-file
$ cp ca.pem          ~/.config/varlink-httpd/server-ca-file

$ VARLINK_BRIDGE_URL=https://myhost:1031/ws/sockets/io.systemd.Hostname \
    varlinkctl call exec:/usr/libexec/varlinkctl-http \
    io.systemd.Hostname.Describe '{}'
```

## SSH key authentication

The bridge can authenticate requests using SSH public keys. If you
have an SSH agent running clients authenticate automatically with zero
extra configuration. Note that RSA keys are *not* supported, just
Ed25519 and ECDSA keys.

### Server setup

The bridge discovers authorized keys automatically from these
locations (first match wins):

1. `--authorized-keys=PATH` — explicit CLI flag
2. `/etc/varlink-httpd/authorized_keys` — config file
3. `$CREDENTIALS_DIRECTORY/ssh.authorized_keys.root` — systemd per-service credential (see `systemd.exec(5)`)
4. `/run/credentials/@system/ssh.authorized_keys.root` — system-wide credential (see `systemd.system-credentials(7)`)

The simplest setup is to pass the path explicitly:

```console
$ varlink-httpd --authorized-keys=~/.ssh/authorized_keys
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

### Client setup (key selection)

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


### Combining with TLS

SSH key auth and TLS/mTLS are independent and should be combined. For
example, use regular TLS (not mTLS) for transport encryption and SSH
keys for user authentication:

```console
$ varlink-httpd \
    --cert=server.pem \
    --key=server-key.pem \
    --authorized-keys=~/.ssh/authorized_keys
```

This is recommended because for websocket requests only the initial
"upgrade" request is signed with the ssh key, after the upgrade it is
a plain WebSocket which relies on the underlying TLS for security.
