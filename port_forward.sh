#!/bin/bash
# ===========================
# 端口转发管理：支持 TCP/UDP，成组删除，自动持久化
# ===========================

set -euo pipefail

if ((BASH_VERSINFO[0] < 4)); then
  printf '❌ 当前 Bash 版本过低（%s）。请使用 4.0 或更高版本。\n' "${BASH_VERSINFO[*]}"
  exit 1
fi

# ==== 可选：是否自动为 FORWARD 添加放行（默认开启，设为0可关闭） ====
ENABLE_FILTER_RULES=${ENABLE_FILTER_RULES:-1}

LOCK_FILE=""
LOCK_FD=""
FLOCK_AVAILABLE=0

RESET=$'\e[0m'
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
BLUE=$'\e[34m'
CYAN=$'\e[36m'

supports_color() {
  [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]] && [[ "${TERM:-}" != "dumb" ]]
}

if ! supports_color; then
  RESET=""
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  CYAN=""
fi

if [[ ! "$ENABLE_FILTER_RULES" =~ ^[01]$ ]]; then
  echo -e "⚠️ ${YELLOW}ENABLE_FILTER_RULES 值无效，已重置为 1。${RESET}"
  ENABLE_FILTER_RULES=1
fi

if command -v flock >/dev/null 2>&1; then
  FLOCK_AVAILABLE=1
fi

release_lock() {
  trap - EXIT
  local exit_code=$1

  if [[ -n "${LOCK_FD:-}" ]]; then
    if (( FLOCK_AVAILABLE )); then
      flock -u "$LOCK_FD" || true
    fi
    exec {LOCK_FD}>&-
  fi

  if [[ -n "${LOCK_FILE:-}" && -e "$LOCK_FILE" ]]; then
    rm -f "$LOCK_FILE"
  fi

  exit "$exit_code"
}

acquire_lock() {
  local lock_dir="/run/lock"
  if [[ ! -d "$lock_dir" || ! -w "$lock_dir" ]]; then
    lock_dir="/tmp"
  fi

  LOCK_FILE="$lock_dir/port_forward.lock"
  if ! touch "$LOCK_FILE"; then
    echo -e "❌ ${RED}无法创建锁文件 $LOCK_FILE，请检查权限。${RESET}"
    exit 1
  fi
  exec {LOCK_FD}>"$LOCK_FILE"

  if (( FLOCK_AVAILABLE )); then
    if ! flock -n "$LOCK_FD"; then
      echo -e "❌ ${RED}已有脚本实例正在运行，请稍后重试。${RESET}"
      exit 1
    fi
  else
    echo -e "⚠️ ${YELLOW}未检测到 flock，无法启用并发保护。${RESET}"
  fi

  trap 'release_lock $?' EXIT
}

ensure_dependencies() {
  local missing=() ans old_frontend_set=0 old_frontend_value=""

  if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1; then
    missing+=("iptables")
  fi
  command -v conntrack >/dev/null 2>&1 || missing+=("conntrack-tools")
  command -v netfilter-persistent >/dev/null 2>&1 || missing+=("iptables-persistent")

  if ((${#missing[@]} == 0)); then
    return
  fi

  echo -e "ℹ️ ${YELLOW}检测到缺失依赖：${missing[*]}${RESET}"

  if command -v apt-get >/dev/null 2>&1; then
    if ! read -r -p "🛠️ ${CYAN}是否现在使用 apt-get 安装上述依赖？[y/N]: ${RESET} " ans; then
      echo -e "🛑 ${RED}输入中断，脚本退出。${RESET}"
      exit 1
    fi
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
      echo -e "🛑 ${RED}缺失依赖未安装，脚本退出。${RESET}"
      exit 1
    fi
    echo -e "📦 ${BLUE}开始安装：${missing[*]}${RESET}"
    if [[ -n "${DEBIAN_FRONTEND:-}" ]]; then
      old_frontend_set=1
      old_frontend_value="$DEBIAN_FRONTEND"
    fi
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get update; then
      if (( old_frontend_set )); then
        export DEBIAN_FRONTEND="$old_frontend_value"
      else
        unset DEBIAN_FRONTEND
      fi
      echo -e "❌ ${RED}apt-get update 失败，请手动安装依赖。${RESET}"
      exit 1
    fi
    if ! apt-get install -y --no-install-recommends "${missing[@]}"; then
      if (( old_frontend_set )); then
        export DEBIAN_FRONTEND="$old_frontend_value"
      else
        unset DEBIAN_FRONTEND
      fi
      echo -e "❌ ${RED}安装失败，请手动安装依赖后重试。${RESET}"
      exit 1
    fi
    if (( old_frontend_set )); then
      export DEBIAN_FRONTEND="$old_frontend_value"
    else
      unset DEBIAN_FRONTEND
    fi
    echo -e "✅ ${GREEN}依赖安装完成。${RESET}"
  else
    echo -e "❌ ${RED}未检测到 apt-get，请手动安装：${missing[*]}${RESET}"
    exit 1
  fi
}

wait_main_menu() {
  if ! read -r -p "🔁 ${CYAN}按回车返回主菜单...${RESET} " _; then
    echo -e "🟡 ${YELLOW}检测到输入结束，程序退出。${RESET}"
    exit 0
  fi
}

# 开启 IPv4 转发并持久化

configure_ip_forward() {
  if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    echo -e "❌ ${RED}设置 net.ipv4.ip_forward 失败，请检查内核配置。${RESET}"
    exit 1
  fi

  local sysctl_conf="/etc/sysctl.conf"
  if [[ -f "$sysctl_conf" ]]; then
    if grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "$sysctl_conf"; then
      if ! sed -i 's|^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*|net.ipv4.ip_forward=1|' "$sysctl_conf"; then
        echo -e "❌ ${RED}更新 $sysctl_conf 失败，请手动确认。${RESET}"
        exit 1
      fi
    else
      echo 'net.ipv4.ip_forward=1' >> "$sysctl_conf"
    fi
  else
    echo 'net.ipv4.ip_forward=1' > "$sysctl_conf"
  fi
}

save_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    if ! netfilter-persistent save >/dev/null 2>&1; then
      echo -e "⚠️ ${YELLOW}netfilter-persistent save 执行失败，请手动确认规则是否持久化。${RESET}"
    fi
    return
  fi

  local rules_dir="/etc/iptables" tmp_file=""
  if [[ ! -d "$rules_dir" ]]; then
    if ! mkdir -p "$rules_dir"; then
      echo -e "⚠️ ${YELLOW}无法创建 $rules_dir，规则未持久化。${RESET}"
      return
    fi
  fi

  if ! tmp_file=$(mktemp "$rules_dir/rules.v4.XXXXXX"); then
    echo -e "⚠️ ${YELLOW}无法创建临时文件，规则未持久化。${RESET}"
    return
  fi

  if iptables-save > "$tmp_file"; then
    mv "$tmp_file" "$rules_dir/rules.v4"
  else
    echo -e "⚠️ ${YELLOW}iptables-save 执行失败，规则未持久化。${RESET}"
    rm -f "$tmp_file"
  fi
}

ensure_forward_rules() {
  local proto="$1" b_ip="$2" b_port="$3"
  # 放行去往 B 的新连接与返回流量
  iptables -C FORWARD -p "$proto" -d "$b_ip" --dport "$b_port" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -p "$proto" -d "$b_ip" --dport "$b_port" -j ACCEPT
  iptables -C FORWARD -p "$proto" -s "$b_ip" --sport "$b_port" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -p "$proto" -s "$b_ip" --sport "$b_port" -m state --state ESTABLISHED,RELATED -j ACCEPT
}

remove_forward_rules() {
  local proto="$1" b_ip="$2" b_port="$3"
  iptables -C FORWARD -p "$proto" -d "$b_ip" --dport "$b_port" -j ACCEPT 2>/dev/null \
    && iptables -D FORWARD -p "$proto" -d "$b_ip" --dport "$b_port" -j ACCEPT || true
  iptables -C FORWARD -p "$proto" -s "$b_ip" --sport "$b_port" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    && iptables -D FORWARD -p "$proto" -s "$b_ip" --sport "$b_port" -m state --state ESTABLISHED,RELATED -j ACCEPT || true
}

purge_conntrack_entries() {
  local proto="$1" a_ip="$2" a_port="$3"

  if ! command -v conntrack >/dev/null 2>&1; then
    return 2
  fi

  local args=(-p "$proto" --dport "$a_port")
  if [[ -n "$a_ip" && "$a_ip" != "0.0.0.0/0" && "$a_ip" != "0.0.0.0" && "$a_ip" != "anywhere" ]]; then
    args+=(--dst "$a_ip")
  fi

  local listing
  listing=$(conntrack -L "${args[@]}" 2>/dev/null | grep -v 'flow entries have been' || true)
  if [[ -z "$listing" ]]; then
    return 1
  fi

  local delete_output
  delete_output=$(conntrack -D "${args[@]}" 2>&1 || true)
  if echo "$delete_output" | grep -qE '[1-9][0-9]* flow entries have been deleted'; then
    return 0
  fi

  listing=$(conntrack -L "${args[@]}" 2>/dev/null | grep -v 'flow entries have been' || true)
  [[ -z "$listing" ]] && return 0
  return 1
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  ((port >= 1 && port <= 65535)) || return 1
  return 0
}

validate_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  read -r o1 o2 o3 o4 <<<"$ip"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    [[ -n "$octet" ]] || return 1
    ((octet >= 0 && octet <= 255)) || return 1
  done
  return 0
}

add_rule() {
  local A_PORT all A_IP B_IP B_PORT proto_choice DEST_MATCH protocols added

  if ! read -r -p "🟦 ${CYAN}请输入服务器 A 的端口 (例如 443): ${RESET} " A_PORT; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  if ! validate_port "$A_PORT"; then
    echo -e "❌ ${RED}端口无效，请输入 1-65535 之间的数字。${RESET}"
    wait_main_menu
    return
  fi

  if ! read -r -p "🟪 ${CYAN}是否匹配所有本机IP? [Y/n]: ${RESET} " all; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  all=${all:-Y}
  DEST_MATCH=()
  if [[ "$all" =~ ^[Nn]$ ]]; then
    if ! read -r -p "🟦 ${CYAN}请输入服务器 A 的 IP: ${RESET} " A_IP; then
      echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
      wait_main_menu
      return
    fi
    if ! validate_ipv4 "$A_IP"; then
      echo -e "❌ ${RED}服务器 A 的 IP 无效，请输入合法 IPv4 地址。${RESET}"
      wait_main_menu
      return
    fi
    DEST_MATCH=(-d "$A_IP")
  fi

  if ! read -r -p "🟦 ${CYAN}请输入服务器 B 的 IP: ${RESET} " B_IP; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  if ! validate_ipv4 "$B_IP"; then
    echo -e "❌ ${RED}服务器 B 的 IP 无效，请输入合法 IPv4 地址。${RESET}"
    wait_main_menu
    return
  fi

  if ! read -r -p "🟦 ${CYAN}请输入服务器 B 的端口: ${RESET} " B_PORT; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  if ! validate_port "$B_PORT"; then
    echo -e "❌ ${RED}服务器 B 的端口无效，请输入 1-65535 之间的数字。${RESET}"
    wait_main_menu
    return
  fi

  if ! read -r -p "🔀 ${CYAN}请选择协议 (1: TCP 2: UDP 3: TCP+UDP) [默认1]: ${RESET} " proto_choice; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  proto_choice=${proto_choice:-1}

  case $proto_choice in
    1) protocols=(tcp) ;;
    2) protocols=(udp) ;;
    3) protocols=(tcp udp) ;;
    *) protocols=(tcp) ;;
  esac

  added=0
  local -a existing=()
  for proto in "${protocols[@]}"; do
    if iptables -t nat -C PREROUTING -p "$proto" "${DEST_MATCH[@]}" --dport "$A_PORT" \
      -j DNAT --to-destination "$B_IP:$B_PORT" 2>/dev/null; then
      existing+=("$proto")
    else
      iptables -t nat -A PREROUTING -p "$proto" "${DEST_MATCH[@]}" --dport "$A_PORT" \
        -j DNAT --to-destination "$B_IP:$B_PORT"
      added=1
    fi

    if ! iptables -t nat -C POSTROUTING -p "$proto" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE 2>/dev/null; then
      iptables -t nat -A POSTROUTING -p "$proto" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE
      added=1
    fi

    if [[ "$ENABLE_FILTER_RULES" -eq 1 ]]; then
      ensure_forward_rules "$proto" "$B_IP" "$B_PORT"
    fi
  done

  if [[ "$added" -eq 1 ]]; then
    echo -e "✅ ${GREEN}已更新：A:*:$A_PORT -> $B_IP:$B_PORT (${protocols[*]})${RESET}"
    save_rules
  else
    echo -e "ℹ️ ${YELLOW}所选协议的转发规则已存在，未做变更。${RESET}"
  fi

  if ((${#existing[@]} > 0)); then
    echo -e "📌 ${BLUE}已存在的协议：${existing[*]}${RESET}"
  fi

  wait_main_menu
}

list_rules() {
  echo -e "📋 ${BLUE}当前 NAT PREROUTING DNAT 规则:${RESET}"
  local lines
  lines=$(iptables -t nat -L PREROUTING -n --line-numbers | grep -E 'DNAT' || true)
  if [[ -z "$lines" ]]; then
    echo -e "ℹ️ ${YELLOW}暂无规则。${RESET}"
    wait_main_menu
    return
  fi
  echo "$lines" | awk -v color="$CYAN" -v reset="$RESET" '{printf "%s🔢 %d) %s%s\n", color, NR, $0, reset}'
  wait_main_menu
}

# 内部工具：尝试删除一条 PREROUTING 规则（带/不带 -d）
del_prerouting_variant() {
  local proto="$1" a_ip="$2" a_port="$3" b_ip="$4" b_port="$5"
  # 先尝试带 -d
  iptables -t nat -C PREROUTING -p "$proto" -d "$a_ip" --dport "$a_port" \
    -j DNAT --to-destination "$b_ip:$b_port" 2>/dev/null \
    && iptables -t nat -D PREROUTING -p "$proto" -d "$a_ip" --dport "$a_port" \
       -j DNAT --to-destination "$b_ip:$b_port" && return 0
  # 再尝试不带 -d（当添加时未限定目的IP）
  iptables -t nat -C PREROUTING -p "$proto" --dport "$a_port" \
    -j DNAT --to-destination "$b_ip:$b_port" 2>/dev/null \
    && iptables -t nat -D PREROUTING -p "$proto" --dport "$a_port" \
       -j DNAT --to-destination "$b_ip:$b_port" && return 0
  return 1
}

delete_rule() {
  local rules
  rules=$(iptables -t nat -L PREROUTING -n --line-numbers | grep -E 'DNAT' || true)
  if [[ -z "$rules" ]]; then
    echo -e "ℹ️ ${YELLOW}没有找到任何转发规则。${RESET}"
    wait_main_menu
    return
  fi

  echo -e "🗂️ ${BLUE}当前转发规则列表:${RESET}"
  echo "$rules" | awk -v color="$CYAN" -v reset="$RESET" '{printf "%s🔢 %d) %s%s\n", color, NR, $0, reset}'
  if ! read -r -p "🧹 ${CYAN}请输入要删除的序号: ${RESET} " num; then
    echo -e "🟡 ${YELLOW}输入中断，取消删除。${RESET}"
    wait_main_menu
    return
  fi
  if [[ ! "$num" =~ ^[0-9]+$ ]]; then
    echo -e "❌ ${RED}序号无效，请输入正整数。${RESET}"
    wait_main_menu
    return
  fi
  if (( num <= 0 )); then
    echo -e "❌ ${RED}序号无效，请输入正整数。${RESET}"
    wait_main_menu
    return
  fi
  local line
  line=$(echo "$rules" | sed -n "${num}p")
  if [[ -z "$line" ]]; then
    echo -e "❌ ${RED}未找到该序号，请重试。${RESET}"
    wait_main_menu
    return
  fi

  # 解析：协议、A_IP（目的地址列=第6列）、A_PORT（dpt:）、B_IP/B_PORT（to:）
  local PROTO A_IP A_PORT B_IP B_PORT
  PROTO=$(echo "$line" | awk '{print $3}')
  A_IP=$(echo "$line" | awk '{print $6}')
  A_PORT=$(echo "$line" | grep -oE 'dpt:[0-9]+' | sed 's/dpt://')
  B_IP=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f2)
  B_PORT=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f3)

  if [[ -z "$A_PORT" || -z "$B_IP" || -z "$B_PORT" ]]; then
    echo -e "❌ ${RED}解析失败，无法安全删除。请将 list 的原始输出发给我协助修复。${RESET}"
    wait_main_menu
    return
  fi

  # 按“成组”删除：TCP 和 UDP 都尝试删除对应 PREROUTING & POSTROUTING & FORWARD
  local removed=0
  for p in tcp udp; do
    del_prerouting_variant "$p" "$A_IP" "$A_PORT" "$B_IP" "$B_PORT" && removed=1 || true
    iptables -t nat -C POSTROUTING -p "$p" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE 2>/dev/null \
      && iptables -t nat -D POSTROUTING -p "$p" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE && removed=1 || true
    if [[ "$ENABLE_FILTER_RULES" -eq 1 ]]; then
      remove_forward_rules "$p" "$B_IP" "$B_PORT"
    fi
  done

  if [[ "$removed" -eq 1 ]]; then
    echo -e "🧹 ${GREEN}已成组删除：A:*:$A_PORT -> $B_IP:$B_PORT (含 TCP/UDP、PREROUTING/POSTROUTING)${RESET}"
    save_rules
  else
    echo -e "ℹ️ ${YELLOW}未找到匹配规则（可能已删除）。${RESET}"
  fi

  if [[ "$removed" -eq 1 ]]; then
    if command -v conntrack >/dev/null 2>&1; then
      for p in tcp udp; do
        if purge_conntrack_entries "$p" "$A_IP" "$A_PORT"; then
          echo -e "🧽 ${GREEN}${p^^} 相关连接跟踪已清理，新建连接将立即生效。${RESET}"
        fi
      done
    else
      echo -e "ℹ️ ${YELLOW}未检测到 conntrack 工具（conntrack-tools 包），无法自动清理连接跟踪。${RESET}"
    fi
  fi

  wait_main_menu
}

# ==== 基础检查 ====
if [[ $EUID -ne 0 ]]; then
  echo -e "❌ ${RED}请用 root 运行${RESET}"
  exit 1
fi

acquire_lock
ensure_dependencies
configure_ip_forward

while true; do
  echo -e "${CYAN}==============================${RESET}"
  echo -e "📋 ${BLUE}端口转发管理菜单:${RESET}"
  echo -e "🟢 ${GREEN}1) 添加端口转发${RESET}"
  echo -e "🧹 ${GREEN}2) 删除端口转发（成组）${RESET}"
  echo -e "📖️ ${GREEN}3) 查看当前转发规则${RESET}"
  echo -e "🚪 ${GREEN}0) 退出${RESET}"
  echo -e "${CYAN}==============================${RESET}"
  if ! read -r -p "📌 ${CYAN}请选择操作: ${RESET} " choice; then
    echo -e "🟡 ${YELLOW}检测到输入结束，程序退出。${RESET}"
    exit 0
  fi
  case $choice in
    1) add_rule ;;
    2) delete_rule ;;
    3) list_rules ;;
    0) echo -e "👋 ${GREEN}谢谢使用，脚本退出。${RESET}"; exit 0 ;;
    *) echo -e "❌ ${RED}无效选项，请重试。${RESET}" ;;
  esac
done
