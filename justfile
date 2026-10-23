destdir := env("DESTDIR", "")
prefix := "/usr"
sysconfdir := env("SYSCONFDIR", "/etc")
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"
bridgedir := prefix / "lib/systemd/varlink-bridges"

install: install_server install_client install_config

install_server: (build "release")
	install -Dm755 {{srv_binary}} {{destdir}}{{bindir}}/varlink-httpd
	install -dm755 {{destdir}}{{unitdir}}
	sed 's|@bindir@|{{bindir}}|g' data/varlink-httpd.service.in > {{destdir}}{{unitdir}}/varlink-httpd.service
	install -m644 data/varlink-httpd.socket {{destdir}}{{unitdir}}/varlink-httpd.socket
	install -m644 data/varlink-httpd-vsock.socket {{destdir}}{{unitdir}}/varlink-httpd-vsock.socket

install_client: (build "release")
	install -Dm755 {{helper_binary}} {{destdir}}{{bridgedir}}/http
	ln -sf http {{destdir}}{{bridgedir}}/https
	ln -sf http {{destdir}}{{bridgedir}}/ws
	ln -sf http {{destdir}}{{bridgedir}}/wss
	ln -sf http {{destdir}}{{bridgedir}}/vsock
	ln -sf http {{destdir}}{{bridgedir}}/vsock+tls

install_config:
	install -dm755 {{destdir}}{{sysconfdir}}/varlink-httpd

[private]
build profile:
	cargo build --profile {{profile}} --locked

check: (check_binary_size srv_binary srv_max_size) (check_binary_size helper_binary helper_max_size) (check_binary_size relay_binary relay_max_size)
	cargo fmt --check
	cargo clippy --all-targets --locked -- -W clippy::pedantic -D warnings
	# without default features we catch misplaced cfg(feature) attribute
	cargo clippy --all-targets --no-default-features --locked -- -W clippy::pedantic -D warnings

test:
	cargo test --locked
	# without default features so that cfg(not(feature)) tests run too
	cargo test --no-default-features --locked

# the httpd service
srv_binary := "target/release/varlink-httpd"
# max_size_kb is a bit arbitrary but it should ensure we don't increase size too much
# without noticing. Raised from 4MB for the h2 and WebSocket client of --relay.
srv_max_size := "4608 * 1024"

# the varlinkctl http transport so that varlinkctl can talk over http/ws
helper_binary := "target/release/varlinkctl-http"
helper_max_size := "2 * 1024 * 1024"

# the relay for varlink-httpd nodes behind NAT
relay_binary := "target/release/varlink-relayd"
relay_max_size := "3 * 1024 * 1024"

[script]
check_binary_size binary max_size: (build "release")
	max_size_kb="$(({{max_size}} / 1024 ))"
	cur_size_kb=$(( $(stat --format='%s' {{binary}}) / 1024 ))
	echo "release {{binary}}: ${cur_size_kb}KB / ${max_size_kb}KB"
	if [ "$cur_size_kb" -gt "$max_size_kb" ]; then
	  echo "ERROR: release {{binary}} exceeds limit"
	  exit 1
	fi

# not part of `just install`, a relay runs on its own host rather than on every node
install_relay: (build "release")
	install -Dm755 {{relay_binary}} {{destdir}}{{bindir}}/varlink-relayd
