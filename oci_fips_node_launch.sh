[ -f ~/.ssh/id_rsa.pub ] || ssh-keygen -t rsa -b 4096 -N "" -f ~/.ssh/id_rsa; \
C_ID=$(oci iam compartment list --query "data[0].id" --raw-output); \
S_ID=$(oci network subnet list --compartment-id $C_ID --query "data[0].id" --raw-output); \
AD_NAME=$(oci iam availability-domain list --query "data[0].name" --raw-output); \
IMG_ID=$(oci compute image list --compartment-id $C_ID --operating-system "Canonical Ubuntu" --query "data [?\"operating-system-version\"=='24.04' && contains(\"display-name\", 'aarch64')].id | [0]" --raw-output); \
oci compute instance launch --compartment-id $C_ID --availability-domain "$AD_NAME" \
--shape "VM.Standard.A1.Flex" --shape-config '{"ocpus": 4, "memoryInGBs": 24}' \
--display-name "SECURE-FIPS-DOCKER-NODE" --image-id $IMG_ID --subnet-id $S_ID \
--ssh-authorized-keys-file ~/.ssh/id_rsa.pub \
--user-data "$(echo '#!/bin/bash
set -e
# 1. Kernel FIPS Enforcement
sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"fips=1 /" /etc/default/grub
update-grub

# 2. Sysctl Network Hardening (Zero Backdoor Posture)
cat <<EOF > /etc/sysctl.d/60-hardened.conf
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
kernel.kptr_restrict=2
EOF
sysctl -p /etc/sysctl.d/60-hardened.conf

# 3. Secure OS & Docker Environment
apt-get update && apt-get upgrade -y
apt-get install -y ufw curl openssl
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu

# 4. Strict FIPS SSH Hardening
cat <<EOF > /etc/ssh/sshd_config.d/fips-secure.conf
Protocol 2
PermitRootLogin no
MaxAuthTries 3
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
KexAlgorithms ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF

# 5. Firewall & Finalization
ufw limit 22/tcp && ufw --force enable
systemctl enable --now docker
reboot' | base64 -w0)"
