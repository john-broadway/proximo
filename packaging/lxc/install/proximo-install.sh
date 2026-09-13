#!/usr/bin/env bash

# Copyright (c) 2026 John Broadway
# Author: John Broadway (john-broadway)
# License: Apache-2.0 | https://github.com/john-broadway/proximo/raw/main/LICENSE
# Source: https://github.com/john-broadway/proximo

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

setup_uv

PROXIMO_VERSION="$(get_latest_github_release "john-broadway/proximo")"
msg_info "Installing Proximo ${PROXIMO_VERSION}"
# Debian 13 ships Python 3.13; the venv is built on it on purpose. A uv-managed interpreter lands
# under /root, which the service user cannot traverse and ProtectHome hides (203/EXEC, found live).
$STD uv venv --python /usr/bin/python3 /opt/proximo
$STD uv pip install --python /opt/proximo/bin/python "proximo-proxmox[mcp-http]==${PROXIMO_VERSION}"
cat <<EOF >~/.proximo
${PROXIMO_VERSION}
EOF
msg_ok "Installed Proximo ${PROXIMO_VERSION}"

msg_info "Configuring Proximo"
# The service runs as a dedicated system user, the posture of packaging/optional-daemon-mode.service.example.
id -u proximo &>/dev/null || useradd --system --home-dir /var/lib/proximo --shell /usr/sbin/nologin --user-group proximo
mkdir -p /etc/proximo
(umask 077 && openssl rand -hex 32 >/etc/proximo/mcp-bearer.token)
chown proximo:proximo /etc/proximo/mcp-bearer.token
LOCAL_IP="$(hostname -I | awk '{print $1}')"
cat <<EOF >/etc/proximo/proximo.env
# Proximo, this container. Edit, then: systemctl restart proximo-mcp-http
#
# --- Proxmox connection --------------------------------------------------------------
# The service starts without these and answers tools/list; nothing reaches a Proxmox host
# until they are set. The token file holds exactly USER@REALM!TOKENID=SECRET, owned by the
# proximo user, mode 600. Start with a read-only token; docs/SETUP.md in the repo walks the role.
#PROXIMO_API_BASE_URL=https://pve.example.com:8006/api2/json
#PROXIMO_NODE=pve
#PROXIMO_TOKEN_PATH=/etc/proximo/pve-token
#
# --- PROVE ledger --------------------------------------------------------------------
# Hash-chained, keyed audit log; the key is minted beside it. The directory is the unit's
# LogsDirectory, owned by the proximo user.
PROXIMO_AUDIT_LOG=/var/log/proximo/audit.log
#
# --- MCP over Streamable HTTP --------------------------------------------------------
# Endpoint: http://${LOCAL_IP}:41243/mcp  Bearer: the contents of mcp-bearer.token
PROXIMO_MCP_HTTP_HOST=0.0.0.0
PROXIMO_MCP_HTTP_PORT=41243
PROXIMO_MCP_HTTP_TOKEN_FILE=/etc/proximo/mcp-bearer.token
# Host-header allowlist (DNS-rebind guard): this container's address and name. Add every name
# you reach it by; loopback stays so in-container checks work. "*" disables the guard and is only
# safe behind a reverse proxy that checks Host.
PROXIMO_MCP_HTTP_ALLOWED_HOSTS=${LOCAL_IP},$(hostname),localhost,127.0.0.1
EOF
chmod 600 /etc/proximo/proximo.env
msg_ok "Configured Proximo"

msg_info "Creating Service"
cat <<EOF >/etc/systemd/system/proximo-mcp-http.service
[Unit]
Description=Proximo MCP over Streamable HTTP
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=proximo
Group=proximo
EnvironmentFile=/etc/proximo/proximo.env
ExecStart=/opt/proximo/bin/proximo-mcp-http
Restart=on-failure
RestartSec=5
# Least privilege, as packaging/optional-daemon-mode.service.example; the two directories are
# created by systemd, owned by the proximo user, and are the only writable paths.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=proximo
StateDirectoryMode=0750
LogsDirectory=proximo
LogsDirectoryMode=0750

[Install]
WantedBy=multi-user.target
EOF
systemctl enable -q --now proximo-mcp-http
msg_ok "Created Service"

motd_ssh
customize
cleanup_lxc
