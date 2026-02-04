#!/bin/bash
# ===========================
# 端口转发管理：支持 TCP/UDP/域名转发，成组删除，自动持久化
# ===========================

set -euo pipefail

if ((BASH_VERSINFO[0] < 4)); then
  printf '❌ 当前 Bash 版本过低（%s）。请使用 4.0 或更高版本。\n' "${BASH_VERSINFO[*]}"
  exit 1
fi

# ==== 可选：是否自动为 FORWARD 添加放行（默认开启，设为0可关闭） ====
ENABLE_FILTER_RULES=${ENABLE_FILTER_RULES:-1}

# ==== 域名转发存储文件 ====
DOMAIN_RULES_FILE="/etc/port_forward/domain_rules.conf"
CRON_SCRIPT="/etc/port_forward/domain_resolver.sh"

LOCK_FILE=""
LOCK_FD=""
FLOCK_AVAILABLE=0

# --- 颜色定义 ---
RESET=$'\e[0m'
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
BLUE=$'\e[34m'
CYAN=$'\e[36m'
WHITE=$'\e[1;37m'

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
  WHITE=""
fi

if [[ ! "$ENABLE_FILTER_RULES" =~ ^[01]$ ]]; then
  echo -e "⚠️ ${YELLOW}ENABLE_FILTER_RULES 值无效，已重置为 1。${RESET}"
  ENABLE_FILTER_RULES=1
fi

# --- 辅助输出函数 ---
show_banner() {
  clear
  echo -e "${CYAN}"
  echo "  ____            _     _____                                _ "
  echo " |  _ \ ___  _ __| |_  |  ___|__  _ ____      ____ _ _ __ __| |"
  echo " | |_) / _ \| '__| __| | |_ / _ \| '__\ \ /\ / / _\` | '__/ _\` |"
  echo " |  __/ (_) | |  | |_  |  _| (_) | |   \ V  V / (_| | | | (_| |"
  echo " |_|   \___/|_|   \__| |_|  \___/|_|    \_/\_/ \__,_|_|  \__,_|"
  echo -e "${CYAN} ==========================================================${RESET}"
  echo -e "${WHITE}       端口转发管理工具 - 支持IP/域名转发 v2.0${RESET}"
  echo -e "${CYAN} ==========================================================${RESET}"
  echo ""
}

print_info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
print_error() { echo -e "${RED}[ERROR]${RESET} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${RESET} $1"; }

print_card() {
  local title="$1"
  shift
  echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${GREEN}║${WHITE} $title${RESET}"
  echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${RESET}"
  while [ $# -gt 0 ]; do
    echo -e "${GREEN}║${RESET} $1"
    shift
  done
  echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${RESET}\n"
}

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
    print_error "无法创建锁文件 $LOCK_FILE，请检查权限。"
    exit 1
  fi
  exec {LOCK_FD}>"$LOCK_FILE"

  if (( FLOCK_AVAILABLE )); then
    if ! flock -n "$LOCK_FD"; then
      print_error "已有脚本实例正在运行，请稍后重试。"
      exit 1
    fi
  else
    print_warn "未检测到 flock，无法启用并发保护。"
  fi

  trap 'release_lock $?' EXIT
}

ensure_dependencies() {
  local missing=() ans old_frontend_set=0 old_frontend_value=""

  if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1; then
    missing+=("iptables")
  fi
  command -v conntrack >/dev/null 2>&1 || missing+=("conntrack")
  command -v netfilter-persistent >/dev/null 2>&1 || missing+=("iptables-persistent")

  if ((${#missing[@]} == 0)); then
    return
  fi

  print_info "检测到缺失依赖：${missing[*]}"

  if command -v apt-get >/dev/null 2>&1; then
    if ! read -r -p "   ${CYAN}是否现在使用 apt-get 安装上述依赖？[y/N]: ${RESET}" ans; then
      print_error "输入中断，脚本退出。"
      exit 1
    fi
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
      print_error "缺失依赖未安装，脚本退出。"
      exit 1
    fi
    print_info "开始安装：${missing[*]}"
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
      print_error "apt-get update 失败，请手动安装依赖。"
      exit 1
    fi
    if ! apt-get install -y --no-install-recommends "${missing[@]}"; then
      if (( old_frontend_set )); then
        export DEBIAN_FRONTEND="$old_frontend_value"
      else
        unset DEBIAN_FRONTEND
      fi
      print_error "安装失败，请手动安装依赖后重试。"
      exit 1
    fi
    if (( old_frontend_set )); then
      export DEBIAN_FRONTEND="$old_frontend_value"
    else
      unset DEBIAN_FRONTEND
    fi
    print_success "依赖安装完成。"
  else
    print_error "未检测到 apt-get，请手动安装：${missing[*]}"
    exit 1
  fi
}

wait_main_menu() {
  if ! read -r -p "   ${CYAN}按回车返回主菜单...${RESET}" _; then
    print_warn "检测到输入结束，程序退出。"
    exit 0
  fi
}

# 开启 IPv4 转发并持久化
configure_ip_forward() {
  if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    print_error "设置 net.ipv4.ip_forward 失败，请检查内核配置。"
    exit 1
  fi

  local sysctl_conf="/etc/sysctl.conf"
  if [[ -f "$sysctl_conf" ]]; then
    if grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "$sysctl_conf"; then
      if ! sed -i 's|^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*|net.ipv4.ip_forward=1|' "$sysctl_conf"; then
        print_error "更新 $sysctl_conf 失败，请手动确认。"
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
      print_warn "netfilter-persistent save 执行失败，请手动确认规则是否持久化。"
    fi
    return
  fi

  local rules_dir="/etc/iptables" tmp_file=""
  if [[ ! -d "$rules_dir" ]]; then
    if ! mkdir -p "$rules_dir"; then
      print_warn "无法创建 $rules_dir，规则未持久化。"
      return
    fi
  fi

  if ! tmp_file=$(mktemp "$rules_dir/rules.v4.XXXXXX"); then
    print_warn "无法创建临时文件，规则未持久化。"
    return
  fi

  if iptables-save > "$tmp_file"; then
    mv "$tmp_file" "$rules_dir/rules.v4"
  else
    print_warn "iptables-save 执行失败，规则未持久化。"
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

# ==== 域名相关函数 ====

validate_domain() {
  local domain="$1"
  # 简单的域名验证：至少包含一个点，只包含字母、数字、点和短横线
  # 允许单字符子域名，如 a.example.com
  [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])*(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])*)+$ ]] || return 1
  return 0
}

resolve_domain() {
  local domain="$1"
  local resolved_ip=""

  # 优先使用 dig
  if command -v dig >/dev/null 2>&1; then
    resolved_ip=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
  fi

  # 如果 dig 失败，使用 host
  if [[ -z "$resolved_ip" ]] && command -v host >/dev/null 2>&1; then
    resolved_ip=$(host -t A "$domain" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  fi

  # 如果 host 也失败，使用 getent
  if [[ -z "$resolved_ip" ]] && command -v getent >/dev/null 2>&1; then
    resolved_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk 'NR==1{print $1}')
  fi

  echo "$resolved_ip"
}

ensure_domain_rules_dir() {
  local dir
  dir=$(dirname "$DOMAIN_RULES_FILE")
  if [[ ! -d "$dir" ]]; then
    if ! mkdir -p "$dir"; then
      print_error "无法创建目录 $dir"
      return 1
    fi
  fi
  if [[ ! -f "$DOMAIN_RULES_FILE" ]]; then
    touch "$DOMAIN_RULES_FILE"
  fi
  return 0
}

# 保存域名规则到文件
# 格式：A_PORT|A_IP|DOMAIN|B_PORT|PROTOCOLS|CURRENT_IP
save_domain_rule() {
  local a_port="$1" a_ip="$2" domain="$3" b_port="$4" protocols="$5" current_ip="$6"
  ensure_domain_rules_dir || return 1
  echo "${a_port}|${a_ip}|${domain}|${b_port}|${protocols}|${current_ip}" >> "$DOMAIN_RULES_FILE"
}

# 删除域名规则
remove_domain_rule() {
  local a_port="$1" domain="$2"
  if [[ -f "$DOMAIN_RULES_FILE" ]]; then
    local tmp_file
    tmp_file=$(mktemp)
    grep -v "^${a_port}|.*|${domain}|" "$DOMAIN_RULES_FILE" > "$tmp_file" 2>/dev/null || true
    mv "$tmp_file" "$DOMAIN_RULES_FILE"
  fi
}

# 获取所有域名规则
get_domain_rules() {
  if [[ -f "$DOMAIN_RULES_FILE" ]]; then
    cat "$DOMAIN_RULES_FILE"
  fi
}

# 更新域名规则的当前IP
update_domain_rule_ip() {
  local a_port="$1" domain="$2" new_ip="$3"
  if [[ -f "$DOMAIN_RULES_FILE" ]]; then
    local tmp_file
    tmp_file=$(mktemp)
    while IFS='|' read -r port a_ip dom b_port protocols old_ip; do
      if [[ "$port" == "$a_port" && "$dom" == "$domain" ]]; then
        echo "${port}|${a_ip}|${dom}|${b_port}|${protocols}|${new_ip}"
      else
        echo "${port}|${a_ip}|${dom}|${b_port}|${protocols}|${old_ip}"
      fi
    done < "$DOMAIN_RULES_FILE" > "$tmp_file"
    mv "$tmp_file" "$DOMAIN_RULES_FILE"
  fi
}

# 创建定时解析脚本
create_resolver_script() {
  ensure_domain_rules_dir || return 1
  
  cat > "$CRON_SCRIPT" << 'RESOLVER_SCRIPT'
#!/bin/bash
# 域名转发定时解析脚本
# 由 port_forward.sh 自动生成

DOMAIN_RULES_FILE="/etc/port_forward/domain_rules.conf"
LOG_FILE="/var/log/port_forward_resolver.log"

log_msg() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

resolve_domain() {
  local domain="$1"
  local resolved_ip=""
  if command -v dig >/dev/null 2>&1; then
    resolved_ip=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
  fi
  if [[ -z "$resolved_ip" ]] && command -v host >/dev/null 2>&1; then
    resolved_ip=$(host -t A "$domain" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  fi
  if [[ -z "$resolved_ip" ]] && command -v getent >/dev/null 2>&1; then
    resolved_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk 'NR==1{print $1}')
  fi
  echo "$resolved_ip"
}

if [[ ! -f "$DOMAIN_RULES_FILE" ]]; then
  exit 0
fi

while IFS='|' read -r a_port a_ip domain b_port protocols old_ip; do
  [[ -z "$domain" ]] && continue
  
  new_ip=$(resolve_domain "$domain")
  if [[ -z "$new_ip" ]]; then
    log_msg "ERROR: 无法解析域名 $domain"
    continue
  fi
  
  if [[ "$new_ip" != "$old_ip" ]]; then
    log_msg "INFO: 域名 $domain IP变更: $old_ip -> $new_ip"
    
    # 删除旧规则
    IFS=',' read -ra proto_arr <<< "$protocols"
    for proto in "${proto_arr[@]}"; do
      if [[ -n "$a_ip" && "$a_ip" != "any" ]]; then
        iptables -t nat -D PREROUTING -p "$proto" -d "$a_ip" --dport "$a_port" \
          -j DNAT --to-destination "$old_ip:$b_port" 2>/dev/null || true
      else
        iptables -t nat -D PREROUTING -p "$proto" --dport "$a_port" \
          -j DNAT --to-destination "$old_ip:$b_port" 2>/dev/null || true
      fi
      iptables -t nat -D POSTROUTING -p "$proto" -d "$old_ip" --dport "$b_port" -j MASQUERADE 2>/dev/null || true
    done
    
    # 添加新规则
    for proto in "${proto_arr[@]}"; do
      if [[ -n "$a_ip" && "$a_ip" != "any" ]]; then
        iptables -t nat -A PREROUTING -p "$proto" -d "$a_ip" --dport "$a_port" \
          -j DNAT --to-destination "$new_ip:$b_port"
      else
        iptables -t nat -A PREROUTING -p "$proto" --dport "$a_port" \
          -j DNAT --to-destination "$new_ip:$b_port"
      fi
      if ! iptables -t nat -C POSTROUTING -p "$proto" -d "$new_ip" --dport "$b_port" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -p "$proto" -d "$new_ip" --dport "$b_port" -j MASQUERADE
      fi
    done
    
    # 更新存储的IP
    tmp_file=$(mktemp)
    while IFS='|' read -r port aip dom bport protos oip; do
      if [[ "$port" == "$a_port" && "$dom" == "$domain" ]]; then
        echo "${port}|${aip}|${dom}|${bport}|${protos}|${new_ip}"
      else
        echo "${port}|${aip}|${dom}|${bport}|${protos}|${oip}"
      fi
    done < "$DOMAIN_RULES_FILE" > "$tmp_file"
    mv "$tmp_file" "$DOMAIN_RULES_FILE"
    
    # 保存规则
    if command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
    fi
    
    log_msg "INFO: 域名 $domain 规则已更新"
  fi
done < "$DOMAIN_RULES_FILE"
RESOLVER_SCRIPT

  chmod +x "$CRON_SCRIPT"
}

# 设置定时任务
setup_cron_job() {
  local interval="$1"  # 分钟
  create_resolver_script || return 1
  
  # 删除旧的 cron 任务
  crontab -l 2>/dev/null | grep -v "$CRON_SCRIPT" | crontab - 2>/dev/null || true
  
  # 添加新的 cron 任务
  (crontab -l 2>/dev/null || true; echo "*/$interval * * * * $CRON_SCRIPT") | crontab -
  
  print_success "已设置每 $interval 分钟执行一次域名解析更新"
}

# 移除定时任务
remove_cron_job() {
  crontab -l 2>/dev/null | grep -v "$CRON_SCRIPT" | crontab - 2>/dev/null || true
  print_success "已移除域名解析定时任务"
}

# 检查定时任务状态
check_cron_status() {
  if crontab -l 2>/dev/null | grep -q "$CRON_SCRIPT"; then
    local interval
    interval=$(crontab -l 2>/dev/null | grep "$CRON_SCRIPT" | grep -oE '\*/[0-9]+' | sed 's/\*\///')
    if [[ -n "$interval" ]]; then
      print_info "域名解析定时任务已启用，间隔: ${interval} 分钟"
    else
      print_info "域名解析定时任务已启用"
    fi
    return 0
  else
    print_info "域名解析定时任务未启用"
    return 1
  fi
}

add_rule() {
  local A_PORT all A_IP B_INPUT B_IP B_PORT proto_choice DEST_MATCH protocols added
  local is_domain=0 domain_name=""

  print_card "添加端口转发规则" \
    "支持 IP 地址和域名作为目标" \
    "域名会自动解析为IP并支持定时更新"

  if ! read -r -p "   ${CYAN}请输入本机监听端口 (例如 443): ${RESET}" A_PORT; then
    print_warn "输入中断，取消添加。"
    wait_main_menu
    return
  fi
  if ! validate_port "$A_PORT"; then
    print_error "端口无效，请输入 1-65535 之间的数字。"
    wait_main_menu
    return
  fi

  if ! read -r -p "   ${CYAN}是否匹配所有本机IP? [Y/n]: ${RESET}" all; then
    print_warn "输入中断，取消添加。"
    wait_main_menu
    return
  fi
  all=${all:-Y}
  DEST_MATCH=()
  A_IP=""
  if [[ "$all" =~ ^[Nn]$ ]]; then
    if ! read -r -p "   ${CYAN}请输入本机监听的 IP: ${RESET}" A_IP; then
      print_warn "输入中断，取消添加。"
      wait_main_menu
      return
    fi
    if ! validate_ipv4 "$A_IP"; then
      print_error "本机 IP 无效，请输入合法 IPv4 地址。"
      wait_main_menu
      return
    fi
    DEST_MATCH=(-d "$A_IP")
  fi

  if ! read -r -p "   ${CYAN}请输入目标服务器的 IP 或域名: ${RESET}" B_INPUT; then
    print_warn "输入中断，取消添加。"
    wait_main_menu
    return
  fi

  # 判断输入是 IP 还是域名
  if validate_ipv4 "$B_INPUT"; then
    B_IP="$B_INPUT"
    is_domain=0
  elif validate_domain "$B_INPUT"; then
    domain_name="$B_INPUT"
    is_domain=1
    print_info "检测到域名输入，正在解析..."
    B_IP=$(resolve_domain "$domain_name")
    if [[ -z "$B_IP" ]]; then
      print_error "无法解析域名 $domain_name，请检查域名是否正确。"
      wait_main_menu
      return
    fi
    print_success "域名 $domain_name 解析为 $B_IP"
  else
    print_error "输入无效，请输入合法的 IPv4 地址或域名。"
    wait_main_menu
    return
  fi

  if ! read -r -p "   ${CYAN}请输入目标服务器的端口: ${RESET}" B_PORT; then
    print_warn "输入中断，取消添加。"
    wait_main_menu
    return
  fi
  if ! validate_port "$B_PORT"; then
    print_error "目标端口无效，请输入 1-65535 之间的数字。"
    wait_main_menu
    return
  fi

  echo -e "\n   ${CYAN}请选择协议:${RESET}"
  echo -e "   ${GREEN}1)${RESET} TCP"
  echo -e "   ${GREEN}2)${RESET} UDP"
  echo -e "   ${GREEN}3)${RESET} TCP+UDP"
  if ! read -r -p "   ${CYAN}请选择 [默认1]: ${RESET}" proto_choice; then
    print_warn "输入中断，取消添加。"
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
    local proto_str
    proto_str=$(IFS=','; echo "${protocols[*]}")
    
    if [[ "$is_domain" -eq 1 ]]; then
      # 保存域名规则
      local a_ip_save="${A_IP:-any}"
      save_domain_rule "$A_PORT" "$a_ip_save" "$domain_name" "$B_PORT" "$proto_str" "$B_IP"
      
      print_card "域名转发规则已添加" \
        "本机端口   : $A_PORT" \
        "目标域名   : $domain_name" \
        "解析IP     : $B_IP" \
        "目标端口   : $B_PORT" \
        "协议       : ${protocols[*]}"
      
      print_warn "提示：域名IP可能会变化，建议设置定时解析任务（主菜单选项5）"
    else
      print_card "IP转发规则已添加" \
        "本机端口   : $A_PORT" \
        "目标IP     : $B_IP" \
        "目标端口   : $B_PORT" \
        "协议       : ${protocols[*]}"
    fi
    save_rules
  else
    print_info "所选协议的转发规则已存在，未做变更。"
  fi

  if ((${#existing[@]} > 0)); then
    print_info "已存在的协议：${existing[*]}"
  fi

  wait_main_menu
}

list_rules() {
  print_card "当前端口转发规则" \
    "显示所有 NAT PREROUTING DNAT 规则" \
    "带 [域名] 标记的规则支持自动DNS解析"

  local lines
  lines=$(iptables -t nat -L PREROUTING -n --line-numbers | grep -E 'DNAT' || true)
  if [[ -z "$lines" ]]; then
    print_info "暂无转发规则。"
    wait_main_menu
    return
  fi

  # 加载域名规则映射
  declare -A domain_map
  if [[ -f "$DOMAIN_RULES_FILE" ]]; then
    while IFS='|' read -r a_port a_ip domain b_port protocols current_ip; do
      [[ -n "$current_ip" ]] && domain_map["$current_ip"]="$domain"
    done < "$DOMAIN_RULES_FILE"
  fi

  echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${GREEN}║${WHITE} 序号 │ 协议 │ 本机端口 │ 目标地址                                      ${GREEN}║${RESET}"
  echo -e "${GREEN}╠════════════════════════════════════════════════════════════════════════════╣${RESET}"
  
  local idx=0
  while IFS= read -r line; do
    ((++idx))
    local proto a_port b_ip b_port
    proto=$(echo "$line" | awk '{print $3}')
    a_port=$(echo "$line" | grep -oE 'dpt:[0-9]+' | sed 's/dpt://' || true)
    b_ip=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f2 || true)
    b_port=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f3 || true)
    
    # 如果解析失败，跳过该行
    if [[ -z "$a_port" || -z "$b_ip" || -z "$b_port" ]]; then
      ((idx--)) || true
      continue
    fi
    
    local domain_info=""
    if [[ -n "${domain_map[$b_ip]:-}" ]]; then
      domain_info=" [${YELLOW}${domain_map[$b_ip]}${RESET}]"
    fi
    
    printf "${GREEN}║${RESET} ${CYAN}%3d${RESET}  │ %-4s │ %-8s │ %s:%s%s\n" \
      "$idx" "$proto" "$a_port" "$b_ip" "$b_port" "$domain_info"
  done <<< "$lines"
  
  echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════╝${RESET}"
  
  # 显示域名规则统计
  if [[ -f "$DOMAIN_RULES_FILE" ]] && [[ -s "$DOMAIN_RULES_FILE" ]]; then
    local domain_count
    domain_count=$(wc -l < "$DOMAIN_RULES_FILE")
    print_info "其中 $domain_count 条规则使用域名转发"
  fi
  
  wait_main_menu
}

# 列出域名转发规则
list_domain_rules() {
  print_card "域名转发规则列表" \
    "显示所有域名转发规则及其当前解析IP"

  if [[ ! -f "$DOMAIN_RULES_FILE" ]] || [[ ! -s "$DOMAIN_RULES_FILE" ]]; then
    print_info "暂无域名转发规则。"
    wait_main_menu
    return
  fi

  echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${GREEN}║${WHITE} 序号 │ 本机端口 │ 目标域名                    │ 当前IP          │ 协议  ${GREEN}║${RESET}"
  echo -e "${GREEN}╠════════════════════════════════════════════════════════════════════════════╣${RESET}"
  
  local idx=0
  while IFS='|' read -r a_port a_ip domain b_port protocols current_ip; do
    [[ -z "$domain" ]] && continue
    ((++idx))
    printf "${GREEN}║${RESET} ${CYAN}%3d${RESET}  │ %-8s │ %-27s │ %-15s │ %-5s\n" \
      "$idx" "$a_port" "$domain" "$current_ip" "$protocols"
  done < "$DOMAIN_RULES_FILE"
  
  echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════╝${RESET}"
  
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
  print_card "删除转发规则" \
    "选择要删除的规则序号" \
    "删除时会同时清理TCP/UDP相关规则"

  local rules
  rules=$(iptables -t nat -L PREROUTING -n --line-numbers | grep -E 'DNAT' || true)
  if [[ -z "$rules" ]]; then
    print_info "没有找到任何转发规则。"
    wait_main_menu
    return
  fi

  # 加载域名规则映射
  declare -A domain_map
  if [[ -f "$DOMAIN_RULES_FILE" ]]; then
    while IFS='|' read -r a_port a_ip domain b_port protocols current_ip; do
      [[ -n "$current_ip" ]] && domain_map["$current_ip"]="$domain"
    done < "$DOMAIN_RULES_FILE"
  fi

  echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${GREEN}║${WHITE} 序号 │ 协议 │ 本机端口 │ 目标地址                                      ${GREEN}║${RESET}"
  echo -e "${GREEN}╠════════════════════════════════════════════════════════════════════════════╣${RESET}"
  
  local idx=0
  while IFS= read -r line; do
    ((++idx))
    local proto a_port b_ip b_port
    proto=$(echo "$line" | awk '{print $3}')
    a_port=$(echo "$line" | grep -oE 'dpt:[0-9]+' | sed 's/dpt://' || true)
    b_ip=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f2 || true)
    b_port=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f3 || true)
    
    # 如果解析失败，跳过该行
    if [[ -z "$a_port" || -z "$b_ip" || -z "$b_port" ]]; then
      ((idx--)) || true
      continue
    fi
    
    local domain_info=""
    if [[ -n "${domain_map[$b_ip]:-}" ]]; then
      domain_info=" [${YELLOW}${domain_map[$b_ip]}${RESET}]"
    fi
    
    printf "${GREEN}║${RESET} ${CYAN}%3d${RESET}  │ %-4s │ %-8s │ %s:%s%s\n" \
      "$idx" "$proto" "$a_port" "$b_ip" "$b_port" "$domain_info"
  done <<< "$rules"
  
  echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════╝${RESET}"

  if ! read -r -p "   ${CYAN}请输入要删除的序号: ${RESET}" num; then
    print_warn "输入中断，取消删除。"
    wait_main_menu
    return
  fi
  if [[ ! "$num" =~ ^[0-9]+$ ]]; then
    print_error "序号无效，请输入正整数。"
    wait_main_menu
    return
  fi
  if (( num <= 0 )); then
    print_error "序号无效，请输入正整数。"
    wait_main_menu
    return
  fi
  local line
  line=$(echo "$rules" | sed -n "${num}p")
  if [[ -z "$line" ]]; then
    print_error "未找到该序号，请重试。"
    wait_main_menu
    return
  fi

  # 解析：协议、A_IP（目的地址列=第6列）、A_PORT（dpt:）、B_IP/B_PORT（to:）
  local PROTO A_IP A_PORT B_IP B_PORT
  PROTO=$(echo "$line" | awk '{print $3}')
  A_IP=$(echo "$line" | awk '{print $6}')
  A_PORT=$(echo "$line" | grep -oE 'dpt:[0-9]+' | sed 's/dpt://' || true)
  B_IP=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f2 || true)
  B_PORT=$(echo "$line" | grep -oE 'to:[0-9\.]+:[0-9]+' | cut -d':' -f3 || true)

  if [[ -z "$A_PORT" || -z "$B_IP" || -z "$B_PORT" ]]; then
    print_error "解析失败，无法安全删除。请将 list 的原始输出发给我协助修复。"
    wait_main_menu
    return
  fi

  # 检查是否有关联的域名规则
  local domain_name=""
  if [[ -n "${domain_map[$B_IP]:-}" ]]; then
    domain_name="${domain_map[$B_IP]}"
  fi

  # 按"成组"删除：TCP 和 UDP 都尝试删除对应 PREROUTING & POSTROUTING & FORWARD
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
    # 删除关联的域名规则
    if [[ -n "$domain_name" ]]; then
      remove_domain_rule "$A_PORT" "$domain_name"
      print_success "已删除转发规则：本机:$A_PORT -> $domain_name ($B_IP):$B_PORT"
    else
      print_success "已删除转发规则：本机:$A_PORT -> $B_IP:$B_PORT"
    fi
    save_rules
  else
    print_info "未找到匹配规则（可能已删除）。"
  fi

  if [[ "$removed" -eq 1 ]]; then
    if command -v conntrack >/dev/null 2>&1; then
      for p in tcp udp; do
        if purge_conntrack_entries "$p" "$A_IP" "$A_PORT"; then
          print_success "${p^^} 相关连接跟踪已清理，新建连接将立即生效。"
        fi
      done
    else
      print_info "未检测到 conntrack 工具（conntrack 包），无法自动清理连接跟踪。"
    fi
  fi

  wait_main_menu
}

# 管理定时任务
manage_cron() {
  print_card "域名解析定时任务管理" \
    "设置定时任务以自动更新域名解析IP" \
    "当域名IP变化时自动更新转发规则"

  check_cron_status
  echo ""

  echo -e "   ${CYAN}请选择操作:${RESET}"
  echo -e "   ${GREEN}1)${RESET} 启用/更新定时任务"
  echo -e "   ${GREEN}2)${RESET} 禁用定时任务"
  echo -e "   ${GREEN}3)${RESET} 立即执行一次域名解析"
  echo -e "   ${GREEN}0)${RESET} 返回主菜单"
  
  if ! read -r -p "   ${CYAN}请选择: ${RESET}" cron_choice; then
    print_warn "输入中断，返回主菜单。"
    return
  fi

  case $cron_choice in
    1)
      if ! read -r -p "   ${CYAN}请输入解析间隔（分钟，默认5）: ${RESET}" interval; then
        print_warn "输入中断，返回主菜单。"
        return
      fi
      interval=${interval:-5}
      if [[ ! "$interval" =~ ^[0-9]+$ ]] || (( interval < 1 || interval > 1440 )); then
        print_error "间隔无效，请输入 1-1440 之间的数字。"
        wait_main_menu
        return
      fi
      setup_cron_job "$interval"
      ;;
    2)
      remove_cron_job
      ;;
    3)
      print_info "正在执行域名解析..."
      create_resolver_script
      if [[ -x "$CRON_SCRIPT" ]]; then
        bash "$CRON_SCRIPT"
        print_success "域名解析执行完成，请查看 /var/log/port_forward_resolver.log 了解详情。"
      else
        print_error "解析脚本不存在或不可执行。"
      fi
      ;;
    0)
      return
      ;;
    *)
      print_error "无效选项。"
      ;;
  esac

  wait_main_menu
}

# ==== 基础检查 ====
if [[ $EUID -ne 0 ]]; then
  print_error "请用 root 运行此脚本"
  exit 1
fi

acquire_lock
ensure_dependencies
configure_ip_forward

while true; do
  show_banner
  
  echo -e "   ${CYAN}请选择操作:${RESET}"
  echo -e "   ${GREEN}1)${RESET} 添加端口转发 (支持IP/域名)"
  echo -e "   ${GREEN}2)${RESET} 删除端口转发"
  echo -e "   ${GREEN}3)${RESET} 查看当前转发规则"
  echo -e "   ${GREEN}4)${RESET} 查看域名转发规则"
  echo -e "   ${GREEN}5)${RESET} 管理定时解析任务"
  echo -e "   ${GREEN}0)${RESET} 退出"
  echo ""
  
  if ! read -r -p "   ${CYAN}请选择 [0-5]: ${RESET}" choice; then
    print_warn "检测到输入结束，程序退出。"
    exit 0
  fi
  case $choice in
    1) add_rule ;;
    2) delete_rule ;;
    3) list_rules ;;
    4) list_domain_rules ;;
    5) manage_cron ;;
    0) print_success "谢谢使用，再见！"; exit 0 ;;
    *) print_error "无效选项，请重试。" ;;
  esac
done
