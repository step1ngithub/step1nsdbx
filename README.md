# Step in sandbox
step1nsdbx a.k.a. setting up and launching a [jailed](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md) Firecracker microVM on a linux server as a lightweight and secured sandbox for production.

**Note:** This blog post assumes you are running Ubuntu 24.04 LTS or later on an x86_64 system with hardware virtualization support (Intel VT-x or AMD-V).

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
   - [Optional] Create a dedicated low-privilege user for Firecracker and add it to the `kvm` group for access to `/dev/kvm`:
     ```bash
     POLP="step1nsdbx"
     sudo adduser --system --group "$POLP" --shell /bin/false --home /var/lib/"$POLP"
     sudo usermod -aG kvm "$POLP"
     ```
   - Verify KVM access:
     ```bash
     POLP="step1nsdbx"
     sudo -u "$POLP" bash -c 'kvm-ok'
     ```
     Install if needed: `sudo apt install cpu-checker`.

2. **Install Dependencies:**
   - Update your system then remove no longer required packages:
     ```bash
     sudo apt update && sudo apt upgrade -y
     sudo apt autoremove -y
     ```
   - Install required tools (API interactions, etc.):
     ```bash
     sudo apt install -y curl jq
     ```

3. **Security Considerations:**
   - Verify downloaded files' digest checksum to ensure integrity.
   - Firecracker's default security includes a minimal device model (only virtio-block, virtio-net, and serial console), seccomp-bpf filters limiting ~50 syscalls, and no support for unnecessary features like USB or graphics (reducing attack surface).
   - We use the Jailer to chroot Firecracker into a restricted directory, drop capabilities, run as non-root UID/GID, and apply cgroups for CPU/memory limits.
   - Always use read-only root filesystems for immutability to prevent persistent changes by malware.
   - For networking, use host firewalls to restrict traffic and avoid exposing the VM unnecessarily.
   - Consider monitoring logs and using tools like AppArmor or SELinux for additional host hardening.
> [!TIP]
>
> Review also firecracker team's [prod setup guidelines](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).

## Installation

1. **Download Firecracker Binaries:**
   - Download the latest binary release:
     ```bash
     mkdir "${POLP}-build-dir"
     cd "${POLP}-build-dir"
     ARCH="$(uname -m)"
     release_url="https://github.com/firecracker-microvm/firecracker/releases"
     latest_version=$(basename $(curl -fsSLI -o /dev/null -w  %{url_effective} ${release_url}/latest))
     curl -LO https://github.com/firecracker-microvm/firecracker/releases/download/$latest_version/firecracker-$latest_version-$ARCH.tgz
     ```
   - Extract the Firecracker and Jailer binaries:
     ```bash
     tar -xzf firecracker-$latest_version-$ARCH.tgz
     sudo mv release-$latest_version-$ARCH/firecracker-$latest_version-$ARCH /usr/local/bin/firecracker
     sudo mv release-$latest_version-$ARCH/jailer-$latest_version-$ARCH /usr/local/bin/sdbx-jailer
     # cleaning
     rm -r release-$latest_version-$ARCH firecracker-$latest_version-$ARCH.tgz
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
     curl -fsSL -o sdbx_kernel.bin "https://s3.amazonaws.com/spec.ccfc.min/$latest_kernel_key"
     ```

2. **Create a Root Filesystem:**
   - First, let's set up a TAP interface on the Host to prepare acess via network since the serial will be disabled for the guest VM:
     ```bash
     # Guest VM internet access
     TAP_DEV="tap0"
     TAP_NET="172.16.42"
     MASK_SHORT="/30"
     ## Create the tap device
     sudo ip tuntap add "$TAP_DEV" mode tap
     ## Assign it the tap IP and start up the device
     sudo ip addr add "${TAP_NET}.1${MASK_SHORT}" dev "$TAP_DEV"
     sudo ip link set "$TAP_DEV" up
     
     # Guest VM access via network
     BR_IF="br0"
     BR_NET="172.16.243"
     LOCAL_MASK="/29"
     ## Create the bridge interface
     sudo ip link add name "$BR_IF" type bridge
     ## Add the above tap device to the bridge
     sudo ip link set dev "$TAP_DEV" master "$BR_IF"
     ## Give the bridge an IP address in its subnet pool
     sudo ip address add "${BR_NET}.1${LOCAL_MASK}" dev "$BR_IF"
     sudo ip link set "$BR_IF" up
     ```
   - Setup the host system to [correctly route packet](https://github.com/firecracker-microvm/firecracker/blob/main/docs/network-setup.md) for the guest VM:
     ```bash
     # Enable IPv4 forwarding and NAT so the guest can reach the internet
     echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
     # Host firewall rule
     HOST_IFACE=$(ip -j route list default |jq -r '.[0].dev')
     ##
     sudo nft add table firecracker
     sudo nft 'add chain firecracker postrouting { type nat hook postrouting priority srcnat; policy accept; }'
     sudo nft 'add chain firecracker filter { type filter hook forward priority filter; policy accept; }'
     ## Guest IP masquerade
     sudo nft add rule firecracker postrouting ip saddr "${TAP_NET}.2" oifname "$HOST_IFACE" counter masquerade
     ## Accecpt pkt from tap and redirect to host main net interface
     sudo nft add rule firecracker filter iifname "$TAP_DEV" oifname "$HOST_IFACE" accept

     ## Bridge FW conf: allow traffic to be routed to the guest
     sudo nft add rule firecracker postrouting oifname "$BR_IF" counter masquerade
     ```
   - Build a custom rootfs (e.g., with additional packages):
     - Mount the rootfs:
       ```bash
       sudo apt install -y debootstrap
       mkdir mnt rootfs
       sudo debootstrap --variant=minbase --include=apt,sudo,netplan.io,vim,openssh-server,ufw plucky rootfs https://archive.ubuntu.com/ubuntu/
       dd if=/dev/zero of=sdbx_rootfs.ext4 bs=1M count=1024
       mkfs.ext4 sdbx_rootfs.ext4
       sudo mount -o loop sdbx_rootfs.ext4 mnt
       ssh-keygen -t ed25519 -f sdbx_sk -N ""
       sudo mkdir -p rootfs/root/.ssh
       sudo cp -v sdbx_sk.pub rootfs/root/.ssh/authorized_keys
       sudo bash -c 'echo "hardened-sdbx" > rootfs/etc/hostname'
       sudo cp -a rootfs/* mnt/
       sudo chroot mnt
       ```
     - Inside chroot, install packages:
         - Update and upgrade: `apt update && apt upgrade -y && apt modernize-sources -y`
         - Install essential hardening tools (minimal): `apt install --no-install-recommends -y adduser apparmor`
         - Disable unnecessary services: `systemctl disable --now avahi-daemon cups systemd-resolved`
         - Enable firewall: `ufw --force enable && ufw default deny incoming && ufw allow from 172.16.42.1` (allow host IP)
         - Create non-root user: `adduser --disabled-password zoba && usermod -aG sudo zoba && echo "zoba:s7r0ngp4ssw0rd" | chpasswd`
         - DNS configuration: `echo "nameserver 8.8.8.8" >> /etc/resolv.conf`
         - Kernel hardening: Edit `/etc/sysctl.conf` and add:
           ```
           kernel.kptr_restrict=2
           kernel.dmesg_restrict=1
           net.ipv4.conf.all.rp_filter=1
           net.ipv4.conf.default.rp_filter=1
           net.ipv4.tcp_syncookies=1
           ```
           Apply: `sysctl -p`
         - Enable SSH for tunneling: `systemctl enable ssh && ufw allow 22/tcp`
         - Enable AppArmor: `systemctl enable apparmor && aa-enforce /etc/apparmor.d/*`
         - Remove root password (for autologin; set strong one in production): `passwd -d root`
         - Clean up: `apt autoremove --purge -y && rm -rf /var/cache/apt/*`
         - Exit chroot: `exit`
     - Out of chroot, unmount, and set read-only if desired and for immutability:
       ```bash
       sudo umount mnt
       chmod 444 sdbx_rootfs.ext4
       ```

## Configuring and Launching the VM

Using the Jailer to launch Firecracker in a secured environment applies chroot, cgroups, seccomp, and runs as non-root.

1. **Prepare Jailer Environment:**
   - Create a chroot directory structure:
     ```bash
     SDBXID="sdbx-$(uuidgen -r)"
     sudo mkdir -p "/srv/jailer/firecracker/$SDBXID/root" "/sys/fs/cgroup/firecracker/$SDBXID"
     sudo cp sdbx_kernel.bin sdbx_rootfs.ext4 "/srv/jailer/firecracker/$SDBXID/root/"
     sudo chown -R "$POLP":"$POLP" "/srv/jailer/firecracker/$SDBXID/root" "/sys/fs/cgroup/firecracker/$SDBXID"
     # cleaning
     rm sdbx_kernel.bin sdbx_rootfs.ext4 sdbx_sk.pub
     rmdir mnt
     sudo rm -rf rootfs
     ```

2. **VM Configuration file** (sdbx_config.json content):
   - Set boot source (kernel)
   - Attach root drive (read-only for security)
   - Set machine config (1 vCPU, 1024 MiB RAM)
   - Configure network
   ```bash
   sudo -u "$POLP" bash -c "cat -> /srv/jailer/firecracker/$SDBXID/root/sdbx_config.json"
   ```
   ```json
   {
     "boot-source": {
       "kernel_image_path": "sdbx_kernel.bin",
       "boot_args": "8250.nr_uarts=0 reboot=k panic=1 pci=off ip=172.16.42.2::172.16.42.1:255.255.255.252::eth0:on",
       "initrd_path": null
     },
     "drives": [
       {
         "drive_id": "rootfs",
         "partuuid": null,
         "is_root_device": true,
         "is_read_only": true,
         "cache_type": "Writeback",
         "path_on_host": "sdbx_rootfs.ext4",
         "io_engine": "Sync",
         "rate_limiter": {
            "bandwidth": {
               "size": 100000,
               "one_time_burst": 4096,
               "refill_time": 150
            },
            "ops": {
               "size": 10,
               "refill_time": 250
            }
         },
         "socket": null
       }
     ],
     "machine-config": {
       "vcpu_count": 1,
       "mem_size_mib": 1024,
       "smt": false,
       "track_dirty_pages": false,
       "huge_pages": "None"
     },
     "network-interfaces": [
       {
         "iface_id": "eth0",
         "guest_mac": "00:16:3E:42:DE:AD",
         "host_dev_name": "tap0",
         "rx_rate_limiter": {
             "bandwidth": {
                 "size": 1024,
                 "one_time_burst": 1048576,
                 "refill_time": 1000
             }
         },
         "tx_rate_limiter": {
             "bandwidth": {
                 "size": 1024,
                 "one_time_burst": 1048576,
                 "refill_time": 1000
             }
         }
       }
     ],
     "cpu-config": null,
     "balloon": null,
     "vsock": null,
     "logger": null,
     "metrics": null,
     "mmds-config": null,
     "entropy": null,
     "pmem": [],
     "memory-hotplug": null
   }
   ```
   
3. **Start Firecracker with Jailer:**
   - Launch the sandbox:
     ```bash
     # Limit memory to 512MB
     sudo sdbx-jailer --id "$SDBXID" \
         --exec-file /usr/local/bin/firecracker \
         --uid $(id -u "$POLP") \
         --gid $(id -g "$POLP") \
         --chroot-base-dir /srv/jailer \
         --cgroup-version 2 \
         --cgroup "memory.max=536870912" \
         --resource-limit "no-file=4096" \
         --new-pid-ns \
         --daemonize \
         -- \
         --level debug \
         --log-path "./sdbx_firecracker.log" \
         --config-file "./sdbx_config.json"
     ```
     - This runs Firecracker jailed (non-root UID/GID, seccomp), with resource limits to prevent DoS (cgroups)

4. **Limit API socket exposure:**
   - Use Unix sockets with restricted permissions:
     ```bash
     sudo chmod 200 "/srv/jailer/firecracker/$SDBXID/root/run/firecracker.socket"
     ```
   
6. **Get the VM Config:**
   ```bash
   sudo -u "$POLP" bash -c "curl --unix-socket /srv/jailer/firecracker/$SDBXID/root/run/firecracker.socket \
       -X GET 'http://localhost/vm/config' \
       -H 'Accept: application/json' \
       -H 'Content-Type: application/json'" | jq '.'
   ```

7. **Access the sandbox:**
> [!NOTE]
> 
> Please be aware that the device serial console can be reactivated from within the guest even if **it was disabled at boot**.
   - Network Access: Secure Shell
     ```bash
     ssh -i sdbx_sk root@"${TAP_NET}.2"
     ```
   - Shutdown: From guest or API.
     ```bash
     # API soft shutdown
     sudo -u $POLP bash -c "curl --unix-socket /srv/jailer/firecracker/$SDBXID/root/run/firecracker.socket -i \
        -X PUT 'http://localhost/actions' \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -d '{
              \"action_type\": \"SendCtrlAltDel\"
            }'"
     ```

## Steps for GUI Support

> Firecracker does not natively support graphical hardware, optimizing for headless workloads.
> To add GUI, run a desktop environment in the guest and expose it securely over the network using SSH tunneling or TLS-enabled protocols to mitigate risks like MITM attacks.

1. **Adapt the previously built guest VM to add a Desktop Environment:**
   - Connect to the sdbx:
     ```bash
     ssh -i sdbx_sk root@"${TAP_NET}.2"
     ```
     - Inside the guest VM:
       ```bash
       apt update
       apt install -y xfce4 xrdp  # Lightweight desktop + RDP
       systemctl enable xrdp
       ufw allow 3389/tcp  # RDP port, but we'll tunnel
       ```

2. **Access the GUI Securely from the Host:**
   - **Preferred: SSH Tunneling for RDP/VNC:**
     - Establish SSH tunnel:
       ```bash
       ssh -L 3389:localhost:3389 zoba@"${TAP_NET}.2"
       ```
       - Use RDP client (e.g., remmina) to connect to localhost:3389. Login with guest credentials.
   - **Alternative: TLS-Enabled RDP:**
     - Configure xrdp with certificates: Generate self-signed certs in guest (`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/xrdp/key.pem -out /etc/xrdp/cert.pem`), edit `/etc/xrdp/xrdp.ini` to enable security_layer=tls.
     - Connect with RDP client supporting TLS.
   - Avoid direct exposure; always tunnel.

> [!WARNING]
>
> GUI access increases risks.
> For ultimate security, *prefer headless operation and API/scripting over GUI*.

## Cleaning

### Remove The Firecracker socket
```bash
sudo cat /srv/jailer/firecracker/$SDBXID/root/sdbx_firecracker.log
sudo pkill -9 firecracker
sudo rm /srv/jailer/firecracker/$SDBXID/root/run/firecracker.socket
sudo rm -rf /srv/jailer/firecracker/$SDBXID/root/dev
```

### Remove the Project's dependancies
1. Network
   ```
   sudo ip link del "$TAP_DEV"
   sudo ip link del "$BR_IF"
   sudo nft -a list ruleset
   sudo nft delete rule firecracker postrouting handle 1
   sudo nft delete rule firecracker filter handle 2
   sudo nft delete table firecracker
   ```
2. System
   ```
   # If you have no more guests running on the host
   echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
   # Clear the building directory
   cd .. && rmdir "${POLP}-build-dir"
   ```
