# we have "strip = true in Cargo.toml" so we need to undefine this
%undefine _debugsource_packages

Name:           varlink-httpd
Version:        0.1.0
Release:        %autorelease
Summary:        HTTP bridge for local varlink services

License:        LGPL-2.1-or-later
URL:            https://github.com/mvo5/varlink-proxy-rs
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust >= 1.85
BuildRequires:  just
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros

%description
An HTTP bridge that makes local varlink services available over HTTP and
WebSocket. The main use case is systemd, so only the subset of varlink that
systemd needs is supported right now.

It takes a directory with varlink sockets as the argument and serves whatever
it finds there. Sockets can be added or removed dynamically.

%package -n varlinkctl-http
Summary:        HTTP/WebSocket transport helper for varlinkctl
Requires:       systemd >= 260~

%description -n varlinkctl-http
A bridge helper that lets varlinkctl talk to varlink services over HTTP and
WebSocket (http://, https://, ws://, wss:// URLs). Install into
/usr/lib/systemd/varlink-bridges/ so that varlinkctl discovers it
automatically.

%prep
%autosetup

%build
just build release

%install
DESTDIR=%{buildroot} SYSCONFDIR=%{_sysconfdir} just install

%post
%systemd_post varlink-httpd.service

%preun
%systemd_preun varlink-httpd.service

%postun
%systemd_postun_with_restart varlink-httpd.service

%files
%{_bindir}/varlink-httpd
%{_unitdir}/varlink-httpd.service
%dir %{_sysconfdir}/varlink-httpd

%files -n varlinkctl-http
%{_prefix}/lib/systemd/varlink-bridges/http
%{_prefix}/lib/systemd/varlink-bridges/https
%{_prefix}/lib/systemd/varlink-bridges/ws
%{_prefix}/lib/systemd/varlink-bridges/wss

%changelog
%autochangelog
