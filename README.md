# Step in Sandbox
step1nsdbx a.k.a. setting up and launching a [jailed](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md) Firecracker microVM on a linux server as a lightweight and secured sandbox.

**Note:** This blog post assumes you are running Ubuntu 20.04 LTS or later on an x86_64 system with hardware virtualization support (Intel VT-x or AMD-V). All commands should be run as a non-root user with sudo privileges, unless specified otherwise.

## Prerequisites

1. **Enable KVM and Check Hardware Support:**
   - Ensure your CPU supports virtualization. Check with:
     ```bash
     [[ $(egrep -c '(vmx|svm)' /proc/cpuinfo) -gt 0 ]] && echo "OK" || echo "NOK"
     ```
   - Load the KVM module (for Intel CPUs):
     ```bash
     sudo modprobe kvm_intel
     ```
     Or for AMD:
     ```bash
     sudo modprobe kvm_amd
     ```
   - Create a dedicated low-privilege user for Firecracker and add it to the `kvm` group for access to `/dev/kvm`:
     ```bash
     POLP="step1nsdbx"
     sudo adduser --system --group $POLP --shell /bin/false --home /var/lib/$POLP
     sudo usermod -aG kvm $POLP
     ```
   - Verify KVM access:
     ```bash
     sudo -u $POLP bash -c 'kvm-ok'
     ```
     Install if needed: `sudo apt install cpu-checker`.

2. **Install Dependencies:**
   - Update your system:
     ```bash
     sudo apt update && sudo apt upgrade -y
     ```
   - Install required tools:
     ```bash
     sudo apt install -y curl jq socat screen
     ```
     - `curl` and `jq` for API interactions.
     - `socat` or `screen` for connecting to the serial console.

3. **Security Considerations:**
   - Verify downloaded files' digest checksum to ensure integrity.
   - Firecracker's default security includes a minimal device model (only virtio-block, virtio-net, and serial console), seccomp-bpf filters limiting ~50 syscalls, and no support for unnecessary features like USB or graphics (reducing attack surface).
   - Use the Jailer to chroot Firecracker into a restricted directory, drop capabilities, run as non-root UID/GID, and apply cgroups for CPU/memory limits.
   - Always use read-only root filesystems for immutability to prevent persistent changes by malware.
   - For networking, use host firewalls to restrict traffic and avoid exposing the VM unnecessarily.
   - Monitor logs and use tools like AppArmor or SELinux for additional host hardening.

## Installation

1. **Download Firecracker Binaries:**
   - Download the latest binary release:
     ```bash
     ARCH="$(uname -m)"
     release_url="https://github.com/firecracker-microvm/firecracker/releases"
     latest_version=$(basename $(curl -fsSLI -o /dev/null -w  %{url_effective} ${release_url}/latest))
     mkdir step1nsdbx
     cd step1nsdbx
     curl -LO https://github.com/firecracker-microvm/firecracker/releases/download/$latest_version/firecracker-$latest_version-$ARCH.tgz
     ```
   - Extract the Firecracker and Jailer binaries:
     ```bash
     tar -xzf firecracker-$latest_version-$ARCH.tgz
     sudo mv release-$latest_version-$ARCH/firecracker-$latest_version-$ARCH /usr/local/bin/firecracker
     sudo mv release-$latest_version-$ARCH/jailer-$latest_version-$ARCH /usr/local/bin/jailer
     rm -r release-$latest_version-$ARCH # cleaning
     ```

## Setting Up Kernel and Root Filesystem

Firecracker requires a Linux kernel image and a root filesystem (rootfs) for the guest VM.

1. **Download a Linux Kernel:**
   - Use the latest linux kernel binary:
     ```bash
     CI_VERSION=${latest_version%.*}
     latest_kernel_key=$(curl "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/$CI_VERSION/$ARCH/vmlinux-&list-type=2" \
          | grep -oP "(?<=<Key>)(firecracker-ci/$CI_VERSION/$ARCH/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" \
          | sort -V | tail -1)
     curl -fsSL -o sdbx-vmlinux.bin "https://s3.amazonaws.com/spec.ccfc.min/$latest_kernel_key"
     ```

2. **Create a Root Filesystem:**
   - Build a custom rootfs (e.g., with additional packages):
     - Mount the rootfs:
       ```bash
       sudo apt install -y debootstrap
       mkdir mnt rootfs
       sudo debootstrap --variant=minbase --include=apt,netplan.io,ufw,sudo plucky rootfs http://archive.ubuntu.com/ubuntu/
       dd if=/dev/zero of=sdbx-rootfs.ext4 bs=1M count=500
       mkfs.ext4 sdbx-rootfs.ext4
       chmod 644 sdbx-rootfs.ext4
       sudo mount sdbx-rootfs.ext4 mnt
       ssh-keygen -t ed25519 -f sdbx_sk -N ""
       sudo mkdir -p rootfs/root/.ssh
       sudo cp -v sdbx_sk.pub rootfs/root/.ssh/authorized_keys
       sudo bash -c 'echo "hardened-sdbx" > rootfs/etc/hostname'
       sudo cp -a rootfs/* mnt/
       sudo chroot mnt
       ```
     - Inside chroot, install packages:
         - Update and upgrade: `apt update && apt upgrade -y`
         - Install essential hardening tools (minimal): `apt install --no-install-recommends -y apparmor ufw fail2ban`
         - Disable unnecessary services: `systemctl disable --now avahi-daemon cups systemd-resolved`
         - Enable firewall: `ufw --force enable && ufw default deny incoming && ufw allow from 172.16.0.1` (allow host IP)
         - Create non-root user: `adduser --disabled-password zoba && usermod -aG sudo zoba && echo "zoba:s7r0ngp4ssw0rd" | chpasswd`
         - Kernel hardening: Edit `/etc/sysctl.conf` and add:
           ```
           kernel.kptr_restrict=2
           kernel.dmesg_restrict=1
           net.ipv4.conf.all.rp_filter=1
           net.ipv4.conf.default.rp_filter=1
           net.ipv4.tcp_syncookies=1
           ```
           Apply: `sysctl -p`
         - Enable SSH for tunneling: `apt install -y openssh-server; systemctl enable ssh; ufw allow 22/tcp`
         - Enable AppArmor: `systemctl enable apparmor && aa-enforce /etc/apparmor.d/*`
         - Remove root password (for autologin; set strong one in production): `passwd -d root`
         - Clean up: `apt autoremove --purge -y && rm -rf /var/cache/apt/*`
         - Exit chroot: `exit`
         
     - Out of chroot, unmount, and set read-only if desired:
       ```bash
       sudo umount mnt
       chmod 444 sdbx-rootfs.ext4  # For immutability
       ```

## Configuring and Launching the VM

Using the Jailer to launch Firecracker in a secured environment applies chroot, cgroups, seccomp, and runs as non-root.

1. **Prepare Jailer Environment:**
   - Create a chroot directory structure:
     ```bash
     sudo mkdir -p /srv/jailer/firecracker/sdbx/root /sys/fs/cgroup/firecracker/sdbx
     sudo chown -R $POLP:$POLP /srv/jailer/firecracker/sdbx/root /sys/fs/cgroup/firecracker/sdbx
     ```

2. **Start Firecracker with Jailer:**
   - Launch the sandbox:
     ```bash
     # Limit memory to 512MB
     sudo ./jailer --id sdbx \
         --exec-file /usr/local/bin/firecracker \
         --uid $(id -u $POLP) \
         --gid $(id -g $POLP) \
         --chroot-base-dir /srv/jailer \
         --cgroup-version 2 \
         --cgroup "memory.max=536870912" \
         --new-pid-ns
     ```
     - This runs Firecracker jailed (non-root UID/GID, seccomp), with resource limits to prevent DoS (cgroups)

3. **Limit API socket exposure:**
   - Use Unix sockets with restricted permissions:
     ```bash
     sudo chmod 600 /srv/jailer/firecracker/sdbx/root/run/firecracker.socket
     ```

4. **Configure the VM (in a separate terminal, using the API socket):**
   - Set boot source (kernel):
     ```bash
     sudo -u $POLP bash -c "curl --unix-socket /srv/jailer/firecracker/sdbx/root/run/firecracker.socket -i \
         -X PUT 'http://localhost/boot-source' \
         -H 'Accept: application/json' \
         -H 'Content-Type: application/json' \
         -d '{
               \"kernel_image_path\": \"./sdbx-vmlinux.bin\",
               \"boot_args": \"console=ttyS0 8250.nr_uarts=0 reboot=k panic=1 pci=off\"
            }'"
     ```
   - Attach root drive (read-only for security):
     ```bash
     sudo -u $POLP bash -c "curl --unix-socket /srv/jailer/firecracker/sdbx/root/run/firecracker.socket -i \
         -X PUT 'http://localhost/drives/rootfs' \
         -H 'Accept: application/json' \
         -H 'Content-Type: application/json' \
         -d '{
               \"drive_id\": \"rootfs\",
               \"path_on_host\": \"./sdbx-rootfs.ext4\",
               \"is_root_device\": true,
               \"is_read_only\": true
            }'"
     ```
   - Set machine config (1 vCPU, 512 MiB RAM, with SMT disabled for side-channel protection):
     ```bash
     sudo -u $POLP bash -c "curl --unix-socket /srv/jailer/firecracker/sdbx/root/run/firecracker.socket -i \
         -X PUT 'http://localhost/machine-config' \
         -H 'Accept: application/json' \
         -H 'Content-Type: application/json' \
         -d '{
               \"vcpu_count\": 1,
               \"mem_size_mib\": 512,
               \"smt\": false
            }'"
     ```

5. **Add Secure Networking for Sandbox Connectivity:**
   - Set up a TAP interface with restricted permissions:
     ```bash
     sudo ip tuntap add tap0 mode tap user $POLP
     sudo ip addr add 172.16.0.1/24 dev tap0
     sudo ip link set tap0 up
     sudo ufw allow from 172.16.0.0/24 to any  # Host firewall rule
     ```
   - Configure network in Firecracker:
     ```bash
     sudo -u $POLP bash -c "curl --unix-socket /srv/jailer/firecracker/sdbx/root/run/firecracker.socket -i \
         -X PUT 'http://localhost/network-interfaces/eth0' \
         -H 'Accept: application/json' \
         -H 'Content-Type: application/json' \
         -d '{
               \"iface_id\": \"eth0\",
               \"guest_mac\": \"00:16:3E:42:DE:AD\",
               \"host_dev_name\": \"tap0\"
            }'"
     ```
   - In the guest, configure IP and enable firewall: Add to boot args or init: `ufw enable; ufw allow from 172.16.0.1`.

6. **Start the VM:**
   ```bash
   sudo -u $POLP bash -c "curl --unix-socket /srv/jailer/firecracker/sdbx/root/run/firecracker.socket -i \
       -X PUT 'http://localhost/actions' \
       -H 'Accept: application/json' \
       -H 'Content-Type: application/json' \
       -d '{
             \"action_type\": \"InstanceStart\"
          }'"
   ```

7. **Access the VM:**
   - Connect to the serial console (securely, avoid exposing):
     ```bash
     screen /dev/pts/<ptmx>  # Or socat
     ```
     - Find PTY via logs.
   - Login (harden guest credentials).
   - Shutdown: From guest or API.

## Troubleshooting

- Check logs: Add `--log-path /tmp/firecracker.log --level debug` to Jailer.
- Common errors: Permissions on chroot/files, cgroup limits exceeded.
- For production, use orchestration like containerd with Firecracker runtime.

## Adding GUI Support

Firecracker does not natively support graphical hardware, optimizing for headless workloads. To add GUI, run a desktop environment in the guest and expose it securely over the network. This updated version defaults to secure connections using SSH tunneling or TLS-enabled protocols to mitigate risks like man-in-the-middle attacks.

### Steps for GUI Support

1. **Prepare a Rootfs with Desktop Environment (Hardened):**
   - Use a larger Ubuntu rootfs with minimal desktop:
     - Adapt the previopusly built custom rootfs, mount temporarily:
       ```bash
       sudo mount sdbx-rootfs.ext4 mnt
       sudo chroot mnt
       ```
     - Inside chroot:
       ```bash
       apt update
       apt install -y xfce4 xrdp  # Lightweight desktop + RDP
       systemctl enable xrdp
       ufw allow 3389/tcp  # RDP port, but we'll tunnel
       ```
     - For VNC alternative: `apt install -y tightvncserver;` configure with strong password and TLS if possible.
     - Exit, unmount, set read-only:
       ```bash
       sudo umount mnt
       chmod 444 sdbx-rootfs.ext4
       ```

2. **Launch the VM:**
   - Start as above (with Jailer). Guest boots headless but starts GUI services.

3. **Access the GUI Securely from the Host:**
   - **Preferred: SSH Tunneling for RDP/VNC (Encrypted Connection):**
     - Establish SSH tunnel:
       ```bash
       ssh -L 3389:localhost:3389 zoba@172.16.0.2
       ```
       - Use RDP client (e.g., remmina) to connect to localhost:3389. Login with guest credentials.
     - For VNC: `ssh -L 5901:localhost:5901 zoba@172.16.0.2`, then `vncviewer localhost:1`.
   - **Alternative: TLS-Enabled RDP:**
     - Configure xrdp with certificates: Generate self-signed certs in guest (`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/xrdp/key.pem -out /etc/xrdp/cert.pem`), edit `/etc/xrdp/xrdp.ini` to enable security_layer=tls.
     - Connect with RDP client supporting TLS.
   - Avoid direct exposure; always tunnel or use VPN.

**Security Notes for GUI:** GUI access increases risk—use strong, unique passwords; enable 2FA on SSH if possible; restrict ports with firewalls; monitor connections. For ultimate security, *prefer headless operation and API/scripting over GUI*.
