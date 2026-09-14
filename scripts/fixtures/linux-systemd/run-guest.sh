#!/usr/bin/env bash
set -euo pipefail

guest=/fixture/guest
mkdir -p "$guest"/{bin,sbin,usr/lib/systemd,etc/systemd/system,proc,sys,dev,run,tmp,fixture}
chmod 0700 "$guest/fixture"
chmod 1777 "$guest/tmp"
cp /bin/busybox "$guest/bin/busybox"
cp /usr/lib/systemd/systemd "$guest/usr/lib/systemd/systemd"
# Copy only the system manager's declared runtime libraries, preserving their
# absolute locations. The guest has no source/module/host-filesystem mounts.
while IFS= read -r library; do
  mkdir -p "$guest$(dirname "$library")"
  cp -L "$library" "$guest$library"
done < <(ldd /usr/lib/systemd/systemd | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }')
ln -s ../usr/lib/systemd/systemd "$guest/sbin/init"
printf '%s\n' 'root:x:0:0:root:/root:/bin/busybox' > "$guest/etc/passwd"
printf '%s\n' 'root:x:0:' > "$guest/etc/group"
printf '%s\n' 'ID=openuem-fixture' 'PRETTY_NAME="OpenUEM owned systemd fixture"' > "$guest/etc/os-release"
printf '%s\n' 'owned-virtual-machine' > "$guest/etc/openuem-systemd-fixture"
printf '%s\n' '1643d44b8d204f7087b2a3ec0fcb168d' > "$guest/etc/machine-id"
cat > "$guest/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t tmpfs -o mode=0755 tmpfs /run
/bin/busybox mkdir -p /sys/fs/cgroup
/bin/busybox mount -t cgroup2 cgroup2 /sys/fs/cgroup
exec /usr/lib/systemd/systemd --system --unit=openuem-fixture.target --log-target=console
INIT
chmod 0755 "$guest/init"
cat > "$guest/etc/systemd/system/openuem-fixture.target" <<'UNIT'
[Unit]
Description=Owned virtual machine test target
DefaultDependencies=no
Wants=openuem-fixture.service
UNIT
for target in sysinit basic shutdown network-online multi-user; do
  printf '[Unit]\nDescription=Owned inert dependency\nDefaultDependencies=no\n' > "$guest/etc/systemd/system/$target.target"
done
cat > "$guest/etc/systemd/system/openuem-fixture.service" <<'UNIT'
[Unit]
Description=Owned native systemd tests
DefaultDependencies=no
[Service]
Type=exec
ExecStart=/bin/busybox sh /fixture/run-tests
Environment=OPENUEM_TEST_LIVE_SYSTEMD=owned-virtual-machine TMPDIR=/fixture
StandardInput=null
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
UNIT
cat > "$guest/fixture/run-tests" <<'TEST'
#!/bin/busybox sh
/fixture/linuxservice.test -test.v -test.count=1 -test.timeout=2m -test.run='^TestLinuxLiveSystemd'
result=$?
echo "OPENUEM_SYSTEMD_FIXTURE_RESULT=$result"
/bin/busybox poweroff -f
TEST
CGO_ENABLED=0 go test -c -o "$guest/fixture/linuxservice.test" ./internal/linuxservice
(
  cd "$guest"
  find . -print0 | cpio --null --create --format=newc --owner=0:0 --quiet | gzip -1 > /fixture/guest.cpio.gz
)
case "$(dpkg --print-architecture)" in
  arm64) emulator=(qemu-system-aarch64 -machine virt -cpu cortex-a72); console=ttyAMA0 ;;
  amd64) emulator=(qemu-system-x86_64 -machine q35 -cpu max); console=ttyS0 ;;
  *) exit 1 ;;
esac
kernel=(/boot/vmlinuz-*)
[[ "${#kernel[@]}" -eq 1 ]]
for iteration in 1 2 3; do
  status=0
  timeout --signal=TERM --kill-after=5s 180s "${emulator[@]}" \
    -accel tcg -m 768M -smp 2 -nodefaults -nic none -display none -monitor none \
    -serial stdio -no-reboot -kernel "${kernel[0]}" -initrd /fixture/guest.cpio.gz \
    -append "console=$console rdinit=/init panic=1 random.trust_cpu=on openuem_fixture=owned-virtual-machine" \
    > "/fixture/guest-$iteration.log" 2>&1 || status=$?
  cat "/fixture/guest-$iteration.log"
  [[ "$status" -eq 0 ]]
  grep -q '^OPENUEM_SYSTEMD_FIXTURE_RESULT=0' "/fixture/guest-$iteration.log"
  for test in PrivateManager AbsentDefinition OwnedDefinition OwnedEnablement ForeignDefinition; do
    grep -q -- "--- PASS: TestLinuxLiveSystemd$test" "/fixture/guest-$iteration.log"
  done
done
