# RPM spec file for wld
# Cryptographic Authorship Witnessing - Kinetic Proof of Provenance

%global debug_package %{nil}
%global __strip /bin/true

Name:           wld
Version:        1.0.0
Release:        1%{?dist}
Summary:        Cryptographic authorship witnessing daemon

License:        Proprietary
URL:            https://github.com/writerslogic/wld
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.75
BuildRequires:  cargo >= 1.75
BuildRequires:  git
BuildRequires:  systemd-rpm-macros

Requires:       systemd

%description
WritersLogic provides cryptographic authorship witnessing through kinetic
proof of provenance. It captures keystroke dynamics and timing patterns
to create unforgeable evidence of human authorship.

Features:
- Merkle Mountain Range (MMR) append-only log
- Ed25519 digital signatures
- Privacy-preserving keystroke biometrics
- Multi-anchor timestamping (blockchain, Keybase, etc.)
- Forensic analysis toolkit

%package -n wld-ibus
Summary:        IBus integration for wld
Requires:       %{name} = %{version}-%{release}
Requires:       ibus >= 1.5

%description -n wld-ibus
IBus input method engine for wld that captures keystroke dynamics
through the Linux input method framework.

This package provides system-wide keystroke witnessing through IBus
without requiring elevated privileges.

%prep
%autosetup

%build
cargo build --release --package wld_cli

%install
# Create directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/wld
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_userunitdir}
install -d %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_sharedstatedir}/wld
install -d %{buildroot}%{_localstatedir}/log/wld
install -d %{buildroot}%{_datadir}/doc/%{name}
install -d %{buildroot}%{_datadir}/ibus/component

# Install binaries
install -p -m 755 target/release/wld %{buildroot}%{_bindir}/wld
install -p -m 755 target/release/wld-native-messaging-host %{buildroot}%{_bindir}/wld-native-messaging-host

# Install man pages
install -p -m 644 docs/man/wld.1 %{buildroot}%{_mandir}/man1/wld.1

# Install systemd units
install -p -m 644 apps/wld_cli/packaging/linux/systemd/wld.service %{buildroot}%{_unitdir}/wld.service
install -p -m 644 apps/wld_cli/packaging/linux/systemd/wld.socket %{buildroot}%{_unitdir}/wld.socket
install -p -m 644 apps/wld_cli/packaging/linux/systemd/wld-user.service %{buildroot}%{_userunitdir}/wld.service
install -p -m 644 apps/wld_cli/packaging/linux/systemd/wld-ibus.service %{buildroot}%{_userunitdir}/wld-ibus.service

# Install config
install -p -m 640 configs/config.example.toml %{buildroot}%{_sysconfdir}/wld/config.toml.default

# Install environment file
cat > %{buildroot}%{_sysconfdir}/wld/environment << 'EOF'
# Environment variables for wld
# WLD_LOG_LEVEL=info
# WLD_DATA_DIR=/var/lib/wld
# WLD_CONFIG=/etc/wld/config.toml
EOF

# Install documentation
install -p -m 644 LICENSE %{buildroot}%{_datadir}/doc/%{name}/LICENSE
install -p -m 644 README.md %{buildroot}%{_datadir}/doc/%{name}/README.md

# Install IBus component (if available)
if [ -f apps/wld_cli/packaging/linux/systemd/wld-ibus.xml ]; then
    sed 's|/usr/local/bin|/usr/bin|g' apps/wld_cli/packaging/linux/systemd/wld-ibus.xml > %{buildroot}%{_datadir}/ibus/component/wld.xml
    chmod 644 %{buildroot}%{_datadir}/ibus/component/wld.xml
fi

%pre
# Create wld user and group
getent group wld >/dev/null || groupadd -r wld
getent passwd wld >/dev/null || \
    useradd -r -g wld -d %{_sharedstatedir}/wld -s /sbin/nologin \
    -c "WritersLogic Daemon" wld
exit 0

%post
%systemd_post wld.service wld.socket

# Create default config if it doesn't exist
if [ ! -f %{_sysconfdir}/wld/config.toml ]; then
    cp %{_sysconfdir}/wld/config.toml.default %{_sysconfdir}/wld/config.toml
    chmod 640 %{_sysconfdir}/wld/config.toml
    chown root:wld %{_sysconfdir}/wld/config.toml
fi

# Set ownership on data directories
chown -R wld:wld %{_sharedstatedir}/wld
chown -R wld:wld %{_localstatedir}/log/wld

%preun
%systemd_preun wld.service wld.socket

%postun
%systemd_postun_with_restart wld.service wld.socket

%post -n wld-ibus
# Restart IBus to pick up the new component
if command -v ibus >/dev/null 2>&1; then
    ibus restart 2>/dev/null || true
fi

%postun -n wld-ibus
# Restart IBus after removal
if command -v ibus >/dev/null 2>&1; then
    ibus restart 2>/dev/null || true
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/wld
%{_bindir}/wld-native-messaging-host
%{_mandir}/man1/wld.1*
%{_unitdir}/wld.service
%{_unitdir}/wld.socket
%{_userunitdir}/wld.service
%dir %{_sysconfdir}/wld
%config(noreplace) %attr(640,root,wld) %{_sysconfdir}/wld/config.toml.default
%config(noreplace) %attr(640,root,wld) %{_sysconfdir}/wld/environment
%dir %attr(750,wld,wld) %{_sharedstatedir}/wld
%dir %attr(750,wld,wld) %{_localstatedir}/log/wld
%{_datadir}/doc/%{name}/

%files -n wld-ibus
%{_bindir}/wld-ibus
%{_userunitdir}/wld-ibus.service
%{_datadir}/ibus/component/wld.xml

%changelog
* Mon Jan 27 2025 David Condrey <david@condrey.dev> - 1.0.0-1
- Initial release
- Cryptographic authorship witnessing daemon
- witnessctl control utility
- IBus input method engine integration
- Systemd service files for system and user services
