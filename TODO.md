# TODOs

## `varlink-httpd`

* `--trust=` currently accepts any valid cert in the handshake. Evaluate support for
  subject allowlist, CRL, OCSP etc.

* The server certificate and key are read once at start, while the client CA is
  re-read when it changes, so rotating `cert`/`key` credentials still needs a restart.
  A reload has to swap both or neither: the pair is validated together and the two
  credential files can be caught mid-refresh. Rotating also invalidates every
  client pin of a generated certificate.

* No way to select the auth mechanism via credential; `--auth=` is a flag only,
  so a deployment configured entirely through the credstore still needs a unit
  drop-in. Think about adding a way to configure this via credential, too.

* Nothing bounds TLS handshakes. Every accepted connection is spawned into its
  own task before anything authenticates it, and a peer that stalls mid-handshake
  keeps that task, so an unauthenticated client can pin an unbounded number of
  them. Wants a concurrency limit and a handshake timeout.

* The 401 body is the joined authenticator errors, so an unauthenticated caller
  learns which mechanisms are enabled and why each one rejected it. Return
  something generic and keep the detail in the log.

## `varlinkctl-http`

* `server-ca-file` and `client-cert-file`/`client-key-file` are on-per-client
  rather than one-per-host, so a client talking to several servers can only
  ever present one identity and trust one CA.

* `known-hosts` TOFU is currently enabled by default, should it be opt-in?
