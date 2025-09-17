#!/bin/bash
# ===========================
# 端口转发管理：支持 TCP/UDP，成组删除，自动持久化
# ===========================

set -e

# ==== 可选：是否自动为 FORWARD 添加放行（默认开启，设为0可关闭） ====
ENABLE_FILTER_RULES=1

RESET=$'\e[0m'
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
BLUE=$'\e[34m'
CYAN=$'\e[36m'

wait_main_menu() {
  if ! read -r -p "🔁 ${CYAN}按回车返回主菜单...${RESET} " _; then
    echo -e "🟡 ${YELLOW}检测到输入结束，程序退出。${RESET}"
    exit 0
  fi
}

# ==== 基础检查 ====
if [[ $EUID -ne 0 ]]; then
  echo -e "❌ ${RED}请用 root 运行${RESET}"; exit 1
fi

# 开启 IPv4 转发并持久化
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

save_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null
  elif [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4
  else
    echo -e "⚠️ ${YELLOW}警告：未检测到持久化工具，重启后可能失效（可安装 iptables-persistent）${RESET}"
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

  if ! read -p "🟦 ${CYAN}请输入服务器 A 的端口 (例如 443): ${RESET} " A_PORT; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  if ! validate_port "$A_PORT"; then
    echo -e "❌ ${RED}端口无效，请输入 1-65535 之间的数字。${RESET}"
    wait_main_menu
    return
  fi

  if ! read -p "🟪 ${CYAN}是否匹配所有本机IP? [Y/n]: ${RESET} " all; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  all=${all:-Y}
  DEST_MATCH=()
  if [[ "$all" =~ ^[Nn]$ ]]; then
    if ! read -p "🟦 ${CYAN}请输入服务器 A 的 IP: ${RESET} " A_IP; then
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

  if ! read -p "🟦 ${CYAN}请输入服务器 B 的 IP: ${RESET} " B_IP; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  if ! validate_ipv4 "$B_IP"; then
    echo -e "❌ ${RED}服务器 B 的 IP 无效，请输入合法 IPv4 地址。${RESET}"
    wait_main_menu
    return
  fi

  if ! read -p "🟦 ${CYAN}请输入服务器 B 的端口: ${RESET} " B_PORT; then
    echo -e "🟡 ${YELLOW}输入中断，取消添加。${RESET}"
    wait_main_menu
    return
  fi
  if ! validate_port "$B_PORT"; then
    echo -e "❌ ${RED}服务器 B 的端口无效，请输入 1-65535 之间的数字。${RESET}"
    wait_main_menu
    return
  fi

  if ! read -p "🔀 ${CYAN}请选择协议 (1: TCP 2: UDP 3: TCP+UDP) [默认1]: ${RESET} " proto_choice; then
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
  if ! read -p "🧹 ${CYAN}请输入要删除的序号: ${RESET} " num; then
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

  wait_main_menu
}

while true; do
  echo -e "${CYAN}==============================${RESET}"
  echo -e "📋 ${BLUE}端口转发管理菜单:${RESET}"
  echo -e "🟢 ${GREEN}1) 添加端口转发${RESET}"
  echo -e "🧹 ${GREEN}2) 删除端口转发（成组）${RESET}"
  echo -e "📖️ ${GREEN}3) 查看当前转发规则${RESET}"
  echo -e "🚪 ${GREEN}0) 退出${RESET}"
  echo -e "${CYAN}==============================${RESET}"
  if ! read -p "📌 ${CYAN}请选择操作: ${RESET} " choice; then
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
