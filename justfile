destdir := env("DESTDIR", "")
prefix := "/usr"
sysconfdir := env("SYSCONFDIR", "/etc")
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"
bridgedir := prefix / "lib/systemd/varlink-bridges"
# /etc/polkit-1/rules.d overrides this vendor dir
polkitrulesdir := prefix / "share/polkit-1/rules.d"
sysusersdir := prefix / "lib/sysusers.d"
tmpfilesdir := prefix / "lib/tmpfiles.d"

install: install_server install_client

install_server: (build "release") install_config install_polkit
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
	install -Dm644 data/varlink-httpd.sysusers {{destdir}}{{sysusersdir}}/varlink-httpd.conf
	install -Dm644 data/varlink-httpd.tmpfiles {{destdir}}{{tmpfilesdir}}/varlink-httpd.conf

# without this rule polkit denies the DynamicUser every privileged varlink call
install_polkit:
	install -Dm644 data/10-varlink-httpd.rules {{destdir}}{{polkitrulesdir}}/10-varlink-httpd.rules

[private]
build profile:
	cargo build --profile {{profile}} --locked

check: check_srv_binary_size check_helper_binary_size
	cargo fmt --check
	cargo clippy --all-targets --locked -- -W clippy::pedantic

test:
	cargo test --locked

# the httpd service
srv_binary := "target/release/varlink-httpd"
# max_size_kb is a bit arbitrary but it should ensure we don't increase size too much
# without noticing
srv_max_size := "4 * 1024 * 1024"

# the varlinkctl http transport so that varlinkctl can talk over http/ws
helper_binary := "target/release/varlinkctl-http"
helper_max_size := "2 * 1024 * 1024"

[script]
check_srv_binary_size:
	cargo build --release --locked
	max_size_kb="$(({{srv_max_size}} / 1024 ))"
	cur_size_kb=$(( $(stat --format='%s' {{srv_binary}}) / 1024 ))
	echo "release varlink-httpd binary: ${cur_size_kb}KB / ${max_size_kb}KB"
	if [ "$cur_size_kb" -gt "$max_size_kb" ]; then
	  echo "ERROR: release binary exceeds limit"
	  exit 1
	fi

[script]
check_helper_binary_size:
	cargo build --release --locked
	max_size_kb="$(({{helper_max_size}} / 1024 ))"
	cur_size_kb=$(( $(stat --format='%s' {{helper_binary}}) / 1024 ))
	echo "release varlinkctl-http binary: ${cur_size_kb}KB / ${max_size_kb}KB"
	if [ "$cur_size_kb" -gt "$max_size_kb" ]; then
	  echo "ERROR: release varlinkctl-http binary exceeds limit"
	  exit 1
	fi
