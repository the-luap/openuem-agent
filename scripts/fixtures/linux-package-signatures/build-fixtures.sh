#!/bin/sh
set -eu
umask 077
[ "${OPENUEM_TEST_LINUX_PACKAGE_SIGNATURES:-}" = owned-isolated-publishers ]
[ "$(id -u)" = 0 ]
[ "$(stat -f -c %T /fixture)" = tmpfs ]
install -d -m 0700 /fixture/gnupg
export GNUPGHOME=/fixture/gnupg
gpg --batch --passphrase '' --quick-generate-key 'OpenUEM isolated package fixture <fixture@example.invalid>' rsa3072 sign 0
fingerprint=$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" {print $10; exit}')
keyid=$fingerprint
mkdir -p /fixture/deb/DEBIAN /fixture/deb/usr/share/openuem-signature-fixture /fixture/trust/rpm /fixture/trust/deb/policies/"$keyid" /fixture/trust/deb/keyrings/"$keyid"
cat > /fixture/deb/DEBIAN/control <<'CONTROL'
Package: openuem-signature-fixture
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: OpenUEM fixture <fixture@example.invalid>
Description: Inert isolated package signature fixture
CONTROL
printf 'inert signature fixture\n' > /fixture/deb/usr/share/openuem-signature-fixture/data
chmod 0755 /fixture/deb/DEBIAN
dpkg-deb --root-owner-group --build /fixture/deb /fixture/unsigned.deb
cp /fixture/unsigned.deb /fixture/signed.deb
# Sign the Debian signature stream with SHA-256 explicitly. The distribution's
# debsigs wrapper forces the obsolete --openpgp SHA-1 default.
ar p /fixture/signed.deb debian-binary control.tar.xz data.tar.xz > /fixture/deb-signature-input
gpg --batch --yes --digest-algo SHA256 --local-user "$fingerprint" --detach-sign --output /fixture/_gpgorigin /fixture/deb-signature-input
ar q /fixture/signed.deb /fixture/_gpgorigin
gpg --batch --export "$fingerprint" > /fixture/trust/deb/keyrings/"$keyid"/publisher.gpg
gpg --batch --armor --export "$fingerprint" > /fixture/trust/rpm/publisher.key
cat > /fixture/trust/deb/policies/"$keyid"/openuem.pol <<POLICY
<?xml version="1.0"?>
<!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
<Policy xmlns="https://www.debian.org/debsig/1.0/">
  <Origin Name="OpenUEM" id="$keyid" Description="OpenUEM package publisher"/>
  <Selection><Required Type="origin" File="publisher.gpg" id="$fingerprint"/></Selection>
  <Verification><Required Type="origin" File="publisher.gpg" id="$fingerprint"/></Verification>
</Policy>
POLICY
debsig-verify --policies-dir /fixture/trust/deb/policies --keyrings-dir /fixture/trust/deb/keyrings --use-policy openuem.pol /fixture/signed.deb
mkdir -p /fixture/rpmbuild/SPECS /fixture/rpmbuild/SOURCES /fixture/tmp /fixture/rpmdb
cat > /fixture/rpmbuild/SPECS/fixture.spec <<'SPEC'
Name: openuem-signature-fixture
Version: 1.0
Release: 1
Summary: Inert isolated package signature fixture
License: MIT
BuildArch: noarch
%description
Inert isolated package signature fixture.
%install
mkdir -p %{buildroot}/usr/share/openuem-signature-fixture
printf 'inert signature fixture\n' > %{buildroot}/usr/share/openuem-signature-fixture/data
%files
/usr/share/openuem-signature-fixture/data
SPEC
rpmbuild --dbpath /fixture/rpmdb --define '_tmppath /fixture/tmp' --define '_buildhost fixture.invalid' --define '_topdir /fixture/rpmbuild' -bb /fixture/rpmbuild/SPECS/fixture.spec
cp /fixture/rpmbuild/RPMS/noarch/*.rpm /fixture/unsigned.rpm
cp /fixture/unsigned.rpm /fixture/signed.rpm
rpmsign --define "_gpg_name $fingerprint" --define '_gpg_path /fixture/gnupg' --define '__gpg /usr/bin/gpg' --addsign /fixture/signed.rpm
printf '%s\n' "$fingerprint" > /fixture/publisher-fingerprint
cp -R /fixture/trust/deb /fixture/trust/rpm /etc/openuem/package-signing/

# This second key is never provisioned as an authorized publisher.
install -d -m 0700 /fixture/foreign-gnupg
export GNUPGHOME=/fixture/foreign-gnupg
gpg --batch --passphrase '' --quick-generate-key 'Foreign isolated package fixture <foreign@example.invalid>' rsa3072 sign 0
foreign=$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" {print $10; exit}')
gpg --batch --yes --digest-algo SHA256 --local-user "$foreign" --detach-sign --output /fixture/_gpgorigin /fixture/deb-signature-input
cp /fixture/unsigned.deb /fixture/foreign.deb
ar q /fixture/foreign.deb /fixture/_gpgorigin
cp /fixture/unsigned.rpm /fixture/foreign.rpm
rpmsign --define "_gpg_name $foreign" --define '_gpg_path /fixture/foreign-gnupg' --define '__gpg /usr/bin/gpg' --addsign /fixture/foreign.rpm
gpg --batch --armor --export "$foreign" > /fixture/foreign.key

# No private signing material is needed by the verifier tests.
gpgconf --kill all
GNUPGHOME=/fixture/gnupg gpgconf --kill all
rm -rf /fixture/gnupg /fixture/foreign-gnupg
