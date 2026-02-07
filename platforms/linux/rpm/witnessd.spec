# RPM spec file for witnessd
# Cryptographic Authorship Witnessing - Kinetic Proof of Provenance

%global debug_package %{nil}
%global __strip /bin/true

Name:           witnessd
Version:        1.0.0
Release:        1%{?dist}
Summary:        Cryptographic authorship witnessing daemon

License:        Proprietary
URL:            https://github.com/writerslogic/witnessd
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.21
BuildRequires:  git
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Recommends:     ibus >= 1.5

%description
Witnessd provides cryptographic authorship witnessing through kinetic
proof of provenance. It captures keystroke dynamics and timing patterns
to create unforgeable evidence of human authorship.

Features:
- Merkle Mountain Range (MMR) append-only log
- Ed25519 digital signatures
- Privacy-preserving keystroke biometrics
- Multi-anchor timestamping (blockchain, Keybase, etc.)
- Forensic analysis toolkit

%package -n witnessd-ibus
Summary:        IBus integration for witnessd
Requires:       %{name} = %{version}-%{release}
Requires:       ibus >= 1.5

%description -n witnessd-ibus
IBus input method engine for witnessd that captures keystroke dynamics
through the Linux input method framework.

This package provides system-wide keystroke witnessing through IBus
without requiring elevated privileges.

%prep
%autosetup

%build
export GOFLAGS="-mod=readonly"
export CGO_ENABLED=0

VERSION=%{version}
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

# Build main daemon
go build -trimpath -ldflags="${LDFLAGS}" -o witnessd ./cmd/witnessd

# Build control utility
go build -trimpath -ldflags="${LDFLAGS}" -o witnessctl ./cmd/witnessctl

# Build IBus engine (needs CGO for some features)
export CGO_ENABLED=1
go build -trimpath -ldflags="${LDFLAGS}" -o witnessd-ibus ./cmd/witnessd-ibus || \
    CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o witnessd-ibus ./cmd/witnessd-ibus

%install
# Create directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/witnessd
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_userunitdir}
install -d %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_sharedstatedir}/witnessd
install -d %{buildroot}%{_localstatedir}/log/witnessd
install -d %{buildroot}%{_datadir}/doc/%{name}
install -d %{buildroot}%{_datadir}/ibus/component

# Install binaries
install -p -m 755 witnessd %{buildroot}%{_bindir}/witnessd
install -p -m 755 witnessctl %{buildroot}%{_bindir}/witnessctl
install -p -m 755 witnessd-ibus %{buildroot}%{_bindir}/witnessd-ibus

# Install man pages
install -p -m 644 docs/man/witnessd.1 %{buildroot}%{_mandir}/man1/witnessd.1
install -p -m 644 docs/man/witnessctl.1 %{buildroot}%{_mandir}/man1/witnessctl.1

# Install systemd units
install -p -m 644 platforms/linux/systemd/witnessd.service %{buildroot}%{_unitdir}/witnessd.service
install -p -m 644 platforms/linux/systemd/witnessd.socket %{buildroot}%{_unitdir}/witnessd.socket
install -p -m 644 platforms/linux/systemd/witnessd-user.service %{buildroot}%{_userunitdir}/witnessd.service
install -p -m 644 platforms/linux/systemd/witnessd-ibus.service %{buildroot}%{_userunitdir}/witnessd-ibus.service

# Install config
install -p -m 640 configs/config.example.toml %{buildroot}%{_sysconfdir}/witnessd/config.toml.default

# Install environment file
cat > %{buildroot}%{_sysconfdir}/witnessd/environment << 'EOF'
# Environment variables for witnessd
# WITNESSD_LOG_LEVEL=info
# WITNESSD_DATA_DIR=/var/lib/witnessd
# WITNESSD_CONFIG=/etc/witnessd/config.toml
EOF

# Install documentation
install -p -m 644 LICENSE %{buildroot}%{_datadir}/doc/%{name}/LICENSE
install -p -m 644 README.md %{buildroot}%{_datadir}/doc/%{name}/README.md

# Install IBus component (with updated binary path)
sed 's|/usr/local/bin|/usr/bin|g' cmd/witnessd-ibus/components/witnessd.xml > %{buildroot}%{_datadir}/ibus/component/witnessd.xml
chmod 644 %{buildroot}%{_datadir}/ibus/component/witnessd.xml

%pre
# Create witnessd user and group
getent group witnessd >/dev/null || groupadd -r witnessd
getent passwd witnessd >/dev/null || \
    useradd -r -g witnessd -d %{_sharedstatedir}/witnessd -s /sbin/nologin \
    -c "Witnessd Daemon" witnessd
exit 0

%post
%systemd_post witnessd.service witnessd.socket

# Create default config if it doesn't exist
if [ ! -f %{_sysconfdir}/witnessd/config.toml ]; then
    cp %{_sysconfdir}/witnessd/config.toml.default %{_sysconfdir}/witnessd/config.toml
    chmod 640 %{_sysconfdir}/witnessd/config.toml
    chown root:witnessd %{_sysconfdir}/witnessd/config.toml
fi

# Set ownership on data directories
chown -R witnessd:witnessd %{_sharedstatedir}/witnessd
chown -R witnessd:witnessd %{_localstatedir}/log/witnessd

%preun
%systemd_preun witnessd.service witnessd.socket

%postun
%systemd_postun_with_restart witnessd.service witnessd.socket

%post -n witnessd-ibus
# Restart IBus to pick up the new component
if command -v ibus >/dev/null 2>&1; then
    ibus restart 2>/dev/null || true
fi

%postun -n witnessd-ibus
# Restart IBus after removal
if command -v ibus >/dev/null 2>&1; then
    ibus restart 2>/dev/null || true
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/witnessd
%{_bindir}/witnessctl
%{_mandir}/man1/witnessd.1*
%{_mandir}/man1/witnessctl.1*
%{_unitdir}/witnessd.service
%{_unitdir}/witnessd.socket
%{_userunitdir}/witnessd.service
%dir %{_sysconfdir}/witnessd
%config(noreplace) %attr(640,root,witnessd) %{_sysconfdir}/witnessd/config.toml.default
%config(noreplace) %attr(640,root,witnessd) %{_sysconfdir}/witnessd/environment
%dir %attr(750,witnessd,witnessd) %{_sharedstatedir}/witnessd
%dir %attr(750,witnessd,witnessd) %{_localstatedir}/log/witnessd
%{_datadir}/doc/%{name}/

%files -n witnessd-ibus
%{_bindir}/witnessd-ibus
%{_userunitdir}/witnessd-ibus.service
%{_datadir}/ibus/component/witnessd.xml

%changelog
* Mon Jan 27 2025 David Condrey <david@condrey.dev> - 1.0.0-1
- Initial release
- Cryptographic authorship witnessing daemon
- witnessctl control utility
- IBus input method engine integration
- Systemd service files for system and user services
