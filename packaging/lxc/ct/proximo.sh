#!/usr/bin/env bash
# Proximo as an LXC on your Proxmox host, one line. Runs on the community-scripts engine
# (github.com/community-scripts/core, MIT) pointed at Proximo's own tree: the engine builds the
# container, then runs install/proximo-install.sh inside it. This script is NOT listed by
# community-scripts, and nothing is posted to their telemetry: the senders are overridden below.
COMMUNITY_SCRIPTS_URL="${COMMUNITY_SCRIPTS_URL:-https://raw.githubusercontent.com/john-broadway/proximo/main/packaging/lxc}"
DIAGNOSTICS=no
# The engine is pinned to a commit: it runs as root on the PVE node, so it moves only by a deliberate
# change here (community-scripts/core @ aee583b, 2026-09-08). Set COMMUNITY_SCRIPTS_CORE_URL to try a newer one.
COMMUNITY_SCRIPTS_CORE_URL="${COMMUNITY_SCRIPTS_CORE_URL:-https://raw.githubusercontent.com/community-scripts/core/aee583b00c826fe66deee9b5f4cc7e413b8de577}"
_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../core}/core/build.func"
source "$_cs_boot" 2>/dev/null || source <(curl -fsSL "${COMMUNITY_SCRIPTS_CORE_URL}/core/build.func")
# Fail closed if the engine ever stops defining what is overridden below: a rename upstream would
# otherwise turn an override into a no-op with nothing failing.
for _fn in diagnostics_check _tm_send post_to_api post_to_api_vm post_progress_to_api post_update_to_api \
  post_tool_to_api post_addon_to_api runtime_script_status_guard check_breaking_change_guard get_header; do
  declare -F "$_fn" >/dev/null || { echo "Refusing to run: the engine no longer defines $_fn; review the overrides in this script first." >&2; exit 1; }
done
# The engine's host preflight asks about diagnostics and reads /usr/local/community-scripts/diagnostics;
# both override the env. Proximo is not in their catalog, so nothing of this install belongs in
# their API: no prompt, no host file written, no send, from the host or the container.
# shellcheck disable=SC2034  # the engine exports DIAGNOSTICS into the container
diagnostics_check() { DIAGNOSTICS=no; }
_tm_send() { :; }; post_to_api() { :; }; post_to_api_vm() { :; }; post_progress_to_api() { :; }
post_update_to_api() { :; }; post_tool_to_api() { :; }; post_addon_to_api() { :; }
# Two more calls leave the host on install and on update: the catalog status guard and the
# breaking-change advisory, both GETs to community-scripts hosts carrying the slug. Proximo is
# not in that catalog, so neither answer applies here.
runtime_script_status_guard() { return 0; }
check_breaking_change_guard() { return 0; }
# The banner. The engine keeps banners in its own repo, fetches them with curl's errors on the
# terminal and caches a copy on the host; this one lives here, so nothing is fetched or written.
get_header() {
  cat <<'PROXIMO_BANNER'
 _____         __   ___
|  __ \        \ \ / (_)
| |__) | __ ___ \ V / _ _ __ ___   ___
|  ___/ '__/ _ \ > < | | '_ ` _ \ / _ \
| |   | | | (_) / . \| | | | | | | (_) |
|_|   |_|  \___/_/ \_\_|_| |_| |_|\___/
PROXIMO_BANNER
}
# Copyright (c) 2026 John Broadway
# Author: John Broadway (john-broadway)
# License: Apache-2.0 | https://github.com/john-broadway/proximo/raw/main/LICENSE
# Source: https://github.com/john-broadway/proximo

APP="Proximo"
var_tags="${var_tags:-proxmox;mcp;ai}"
var_cpu="${var_cpu:-2}"
var_ram="${var_ram:-1024}"
var_disk="${var_disk:-6}"
var_os="${var_os:-debian}"
var_version="${var_version:-13}"
var_unprivileged="${var_unprivileged:-1}"

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources

  if [[ ! -d /opt/proximo ]]; then
    msg_error "No ${APP} Installation Found!"
    exit 1
  fi

  if check_for_gh_release "proximo" "john-broadway/proximo"; then
    msg_info "Stopping Service"
    systemctl stop proximo-mcp-http
    msg_ok "Stopped Service"

    msg_info "Updating ${APP} to ${CHECK_UPDATE_RELEASE#v}"
    $STD uv pip install --python /opt/proximo/bin/python "proximo-proxmox[mcp-http]==${CHECK_UPDATE_RELEASE#v}"
    cat <<VERSION >~/.proximo
${CHECK_UPDATE_RELEASE#v}
VERSION
    msg_ok "Updated ${APP} to ${CHECK_UPDATE_RELEASE#v}"

    msg_info "Starting Service"
    systemctl start proximo-mcp-http
    msg_ok "Started Service"
    msg_ok "Updated successfully!"
  else
    # 1 is "no update". Anything else is the check itself failing (6 DNS, 22 empty answer,
    # 250 no releases) and must not read as "up to date" on a silent, unattended run.
    rc=$?; [[ $rc -eq 1 ]] || exit "$rc"
  fi
  exit
}

start
build_container
description

msg_ok "Completed Successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW}MCP endpoint (Streamable HTTP, bearer required):${CL}"
echo -e "${TAB}${GATEWAY}${BGN}http://${IP}:41243/mcp${CL}"
echo -e "${INFO}${YW}Bearer: /etc/proximo/mcp-bearer.token  Proxmox connection: /etc/proximo/proximo.env${CL}"
