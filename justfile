destdir := env("DESTDIR", "")
prefix := "/usr"
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"
bridgedir := prefix / "lib/systemd/varlink-bridges"

install: install_server install_client

install_server: (build "release")
	install -Dm755 {{srv_binary}} {{destdir}}{{bindir}}/varlink-httpd
	install -dm755 {{destdir}}{{unitdir}}
	sed 's|@bindir@|{{bindir}}|g' data/varlink-httpd.service.in > {{destdir}}{{unitdir}}/varlink-httpd.service

install_client: (build "release")
	install -Dm755 {{helper_binary}} {{destdir}}{{bridgedir}}/http
	ln -sf http {{destdir}}{{bridgedir}}/https
	ln -sf http {{destdir}}{{bridgedir}}/ws
	ln -sf http {{destdir}}{{bridgedir}}/wss

[private]
build profile:
	cargo build --profile {{profile}}

check: check_srv_binary_size check_helper_binary_size
	cargo fmt --check
	cargo clippy -- -W clippy::pedantic

test:
	cargo test

# the httpd service
srv_binary := "target/release/varlink-httpd"
# max_size_kb is a bit arbitrary but it should ensure we don't increase size too much
# without noticing (currently at 3.2MB)
srv_max_size := "4 * 1024 * 1024"

# the varlinkctl http transport so that varlinkctl can talk over http/ws
helper_binary := "target/release/varlinkctl-http"
helper_max_size := "2 * 1024 * 1024"

[script]
check_srv_binary_size:
	cargo build --release
	max_size_kb="$(({{srv_max_size}} / 1024 ))"
	cur_size_kb=$(( $(stat --format='%s' {{srv_binary}}) / 1024 ))
	echo "release binary: ${cur_size_kb}KB / ${max_size_kb}KB"
	if [ "$cur_size_kb" -gt "$max_size_kb" ]; then
	  echo "ERROR: release binary exceeds limit"
	  exit 1
	fi

[script]
check_helper_binary_size:
	cargo build --release
	max_size_kb="$(({{helper_max_size}} / 1024 ))"
	cur_size_kb=$(( $(stat --format='%s' {{helper_binary}}) / 1024 ))
	echo "release varlinkctl-http binary: ${cur_size_kb}KB / ${max_size_kb}KB"
	if [ "$cur_size_kb" -gt "$max_size_kb" ]; then
	  echo "ERROR: release varlinkctl-http binary exceeds limit"
	  exit 1
	fi
