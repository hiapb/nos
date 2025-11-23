#!/bin/bash
# =====================================================
# 高仿一键助手（单脚本版）
# 入口 / 高仿 通用
# =====================================================

# 颜色（黑金风格）
GOLD='\033[38;5;220m'
CYAN='\033[38;5;44m'
GRAY='\033[38;5;245m'
RED='\033[38;5;196m'
GREEN='\033[38;5;82m'
BOLD='\033[1m'
RESET='\033[0m'

# 会话变量（只在当前进程存在，不落盘）
ENTRY_IP=""       # 入口IP（被攻击那个）
GF_IP=""          # 高仿IP
ROLE=""           # 本机身份：entry / gf
LOCAL_WAN_IP=""   # 本机公网IP
REMOTE_WAN_IP=""  # 对端公网IP

TUN_NAME="gf_tun0"
LOCAL_TUN_IP=""
REMOTE_TUN_IP=""

TABLE_ID="200"
TABLE_NAME="gf_route"

NET_IF=""         # 对外网卡
THRESHOLD_G=""    # 触发清洗阈值（Gbps）

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[-] 请使用 root 权限运行（sudo / su）。${RESET}"
        exit 1
    fi
}

pause() {
    read -rp "$(echo -e "${GRAY}按回车继续${RESET}")" _
}

# 自动探测本机出网IP
auto_detect_ip() {
    ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}'
}

# IPv4 -> int
ip2int() {
    local IFS=.
    read -r a b c d <<< "$1"
    echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

# int -> IPv4
int2ip() {
    local ip dec=$1
    for _ in {1..4}; do
        ip=$((dec & 255))${ip:+.}$ip
        dec=$((dec >> 8))
    done
    echo "$ip"
}

# 基于 入口IP / 高仿IP 自动生成一个 10.253.x.y/30 隧道网段
calc_tunnel_ips() {
    local ip1="$ENTRY_IP"
    local ip2="$GF_IP"

    local int1 int2 min_ip max_ip
    int1=$(ip2int "$ip1")
    int2=$(ip2int "$ip2")

    if [ "$int1" -le "$int2" ]; then
        min_ip="$ip1"
        max_ip="$ip2"
    else
        min_ip="$ip2"
        max_ip="$ip1"
    fi

    local IFS=.
    read -r a b c d <<< "$min_ip"

    local x=$(( (c + d*3) % 250 ))   # 0-249
    local y=$(( (d*7) % 252 ))       # /30 对齐

    local net_int=$(( (10<<24) + (253<<16) + (x<<8) + y ))
    local host1_int=$((net_int + 1))
    local host2_int=$((net_int + 2))

    local host1_ip host2_ip
    host1_ip=$(int2ip "$host1_int")
    host2_ip=$(int2ip "$host2_int")

    local intEntry intGf
    intEntry=$(ip2int "$ENTRY_IP")
    intGf=$(ip2int "$GF_IP")

    if [ "$intEntry" -le "$intGf" ]; then
        if [ "$ROLE" = "entry" ]; then
            LOCAL_TUN_IP="$host1_ip"
            REMOTE_TUN_IP="$host2_ip"
        else
            LOCAL_TUN_IP="$host2_ip"
            REMOTE_TUN_IP="$host1_ip"
        fi
    else
        if [ "$ROLE" = "entry" ]; then
            LOCAL_TUN_IP="$host2_ip"
            REMOTE_TUN_IP="$host1_ip"
        else
            LOCAL_TUN_IP="$host1_ip"
            REMOTE_TUN_IP="$host2_ip"
        fi
    fi
}

config_session() {
    echo -e "${GOLD}━━━━━━━━━━ 高仿 DDoS 控制台 ━━━━━━━━━━${RESET}"
    echo -e "${CYAN}${BOLD}             会话参数设置${RESET}"
    echo

    echo -e "${CYAN}本机身份${RESET}"
    echo -e "  ${GOLD}1${RESET}）入口服务器"
    echo -e "  ${GOLD}2${RESET}）高仿服务器"
    read -rp "$(echo -e "${CYAN}请选择 1 或 2: ${RESET}")" r
    case "$r" in
        1) ROLE="entry" ;;
        2) ROLE="gf" ;;
        *) echo -e "${RED}[-] 选择无效${RESET}"; pause; return ;;
    esac

    read -rp "$(echo -e "${CYAN}入口IP: ${RESET}")" ENTRY_IP
    read -rp "$(echo -e "${CYAN}高仿IP: ${RESET}")" GF_IP

    if [ -z "$ENTRY_IP" ] || [ -z "$GF_IP" ]; then
        echo -e "${RED}[-] 入口IP / 高仿IP 不能为空${RESET}"
        pause
        return
    fi

    AUTO_IP=$(auto_detect_ip)
    if [ -n "$AUTO_IP" ]; then
        echo -e "${GRAY}检测到本机出网IP：${AUTO_IP}${RESET}"
        read -rp "$(echo -e "${CYAN}本机公网IP（回车使用检测到的）: ${RESET}")" MY_IP
        MY_IP=${MY_IP:-$AUTO_IP}
    else
        read -rp "$(echo -e "${CYAN}本机公网IP: ${RESET}")" MY_IP
    fi

    if [ "$ROLE" = "entry" ]; then
        LOCAL_WAN_IP="$MY_IP"
        REMOTE_WAN_IP="$GF_IP"
    else
        LOCAL_WAN_IP="$MY_IP"
        REMOTE_WAN_IP="$ENTRY_IP"
    fi

    calc_tunnel_ips

    echo
    echo -e "${GOLD}当前会话配置${RESET}"
    echo -e "  身份:         ${CYAN}$ROLE${RESET}"
    echo -e "  入口IP:       ${CYAN}$ENTRY_IP${RESET}"
    echo -e "  高仿IP:       ${CYAN}$GF_IP${RESET}"
    echo -e "  本机公网IP:   ${CYAN}$LOCAL_WAN_IP${RESET}"
    echo -e "  对端公网IP:   ${CYAN}$REMOTE_WAN_IP${RESET}"
    echo -e "  隧道名称:     ${CYAN}$TUN_NAME${RESET}"
    echo -e "  本机隧道IP:   ${CYAN}$LOCAL_TUN_IP${RESET}"
    echo -e "  对端隧道IP:   ${CYAN}$REMOTE_TUN_IP${RESET}"
    echo -e "  路由表:       ${CYAN}$TABLE_ID $TABLE_NAME${RESET}"
    echo
    pause
}

check_base() {
    if [ -z "$ENTRY_IP" ] || [ -z "$GF_IP" ] || [ -z "$ROLE" ]; then
        echo -e "${RED}[-] 还没设置会话参数，请先执行菜单 1${RESET}"
        pause
        return 1
    fi
    if [ -z "$LOCAL_WAN_IP" ] || [ -z "$REMOTE_WAN_IP" ] || [ -z "$LOCAL_TUN_IP" ] || [ -z "$REMOTE_TUN_IP" ]; then
        echo -e "${RED}[-] 隧道参数未就绪，请重新执行菜单 1${RESET}"
        pause
        return 1
    fi
    return 0
}

init_tunnel() {
    check_base || return

    echo -e "${GRAY}[*] 加载 GRE 模块...${RESET}"
    modprobe ip_gre 2>/dev/null || true

    echo -e "${GRAY}[*] 清理旧隧道: ${TUN_NAME}${RESET}"
    ip tunnel del "$TUN_NAME" 2>/dev/null

    echo -e "${GRAY}[*] 创建隧道 ${TUN_NAME}（本机: $LOCAL_WAN_IP → 对端: $REMOTE_WAN_IP）${RESET}"
    ip tunnel add "$TUN_NAME" mode gre local "$LOCAL_WAN_IP" remote "$REMOTE_WAN_IP" ttl 255

    echo -e "${GRAY}[*] 配置本机隧道IP: ${LOCAL_TUN_IP}/30${RESET}"
    ip addr flush dev "$TUN_NAME" 2>/dev/null
    ip addr add "$LOCAL_TUN_IP"/30 dev "$TUN_NAME"

    echo -e "${GRAY}[*] 启用隧道网卡${RESET}"
    ip link set "$TUN_NAME" up

    echo -e "${GRAY}[*] 检查/添加路由表: $TABLE_ID $TABLE_NAME${RESET}"
    if ! grep -qE "^[[:space:]]*$TABLE_ID[[:space:]]+$TABLE_NAME" /etc/iproute2/rt_tables; then
        echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
    fi

    echo -e "${GRAY}[*] 配置 $TABLE_NAME 表默认走隧道${RESET}"
    ip route flush table "$TABLE_NAME" 2>/dev/null
    ip route add default dev "$TUN_NAME" table "$TABLE_NAME"

    echo
    echo -e "${GREEN}[+] 隧道已初始化${RESET}"
    pause
}

start_clean_manual() {
    check_base || return

    read -rp "$(echo -e "${CYAN}要走高仿清洗的入口IP（回车默认当前入口IP）: ${RESET}")" TARGET
    TARGET=${TARGET:-$ENTRY_IP}

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[-] 入口IP不能为空${RESET}"
        pause
        return
    fi

    echo -e "${GRAY}[*] 为 ${TARGET} 添加策略路由${RESET}"
    ip rule add to "$TARGET" lookup "$TABLE_NAME" priority 10000 2>/dev/null || true

    echo -e "${GREEN}[+] 已开启：${TARGET} 流量将通过隧道 ${TUN_NAME} → ${GF_IP} 清洗${RESET}"
    pause
}

stop_clean_manual() {
    check_base || return

    read -rp "$(echo -e "${CYAN}要停止清洗的入口IP（回车默认当前入口IP）: ${RESET}")" TARGET
    TARGET=${TARGET:-$ENTRY_IP}

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[-] 入口IP不能为空${RESET}"
        pause
        return
    fi

    echo -e "${GRAY}[*] 删除 ${TARGET} 的策略路由规则${RESET}"
    ip rule del to "$TARGET" lookup "$TABLE_NAME" 2>/dev/null || true

    echo -e "${GREEN}[+] 已停止：${TARGET} 不再强制走高仿${RESET}"
    pause
}

show_status() {
    echo -e "${GOLD}━━━━━━━━━━ 当前状态 ━━━━━━━━━━${RESET}"
    echo -e "  身份:         ${CYAN}${ROLE:-"(未设置)"}${RESET}"
    echo -e "  入口IP:       ${CYAN}${ENTRY_IP:-"(未设置)"}${RESET}"
    echo -e "  高仿IP:       ${CYAN}${GF_IP:-"(未设置)"}${RESET}"
    echo -e "  本机公网IP:   ${CYAN}${LOCAL_WAN_IP:-"(未设置)"}${RESET}"
    echo -e "  对端公网IP:   ${CYAN}${REMOTE_WAN_IP:-"(未设置)"}${RESET}"
    echo -e "  隧道名称:     ${CYAN}${TUN_NAME}${RESET}"
    echo -e "  本机隧道IP:   ${CYAN}${LOCAL_TUN_IP:-"(未生成)"}${RESET}"
    echo -e "  对端隧道IP:   ${CYAN}${REMOTE_TUN_IP:-"(未生成)"}${RESET}"
    echo -e "  路由表:       ${CYAN}${TABLE_ID} ${TABLE_NAME}${RESET}"
    echo- e "  监控网卡:     ${CYAN}${NET_IF:-"(未设置)"}${RESET}"
    echo -e "  阈值(Gbps):   ${CYAN}${THRESHOLD_G:-"(未设置)"}${RESET}"
    echo -e "${GOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    echo -e "${GRAY}[*] ip tunnel show:${RESET}"
    ip tunnel show

    echo
    echo -e "${GRAY}[*] ip addr show dev ${TUN_NAME}:${RESET}"
    ip addr show dev "$TUN_NAME" 2>/dev/null || echo -e "  设备 ${TUN_NAME} 暂未创建"

    echo
    echo -e "${GRAY}[*] ip rule | grep ${TABLE_NAME}:${RESET}"
    ip rule | grep "$TABLE_NAME" || echo -e "  未找到使用 ${TABLE_NAME} 的规则"

    echo
    echo -e "${GRAY}[*] ip route show table ${TABLE_NAME}:${RESET}"
    ip route show table "$TABLE_NAME" || echo -e "  路由表 ${TABLE_NAME} 暂为空"
    echo
    pause
}

auto_mode() {
    check_base || return

    if [ -z "$NET_IF" ]; then
        echo -e "${GRAY}当前网卡列表：${RESET}"
        ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno|em)[0-9]+' || true
        read -rp "$(echo -e "${CYAN}对外网卡名: ${RESET}")" NET_IF
    fi

    if [ -z "$THRESHOLD_G" ]; then
        read -rp "$(echo -e "${CYAN}触发清洗阈值（Gbps）: ${RESET}")" THRESHOLD_G
    fi

    if [ -z "$NET_IF" ] || [ -z "$THRESHOLD_G" ]; then
        echo -e "${RED}[-] 网卡 / 阈值 未设置完整${RESET}"
        pause
        return
    fi

    local THRESHOLD_MBPS=$((THRESHOLD_G * 1000))

    read -rp "$(echo -e "${CYAN}自动模式保护的入口IP（回车默认当前入口IP）: ${RESET}")" TARGET
    TARGET=${TARGET:-$ENTRY_IP}

    if [ -z "$TARGET" ]; then
        echo -e "${RED}[-] 入口IP不能为空${RESET}"
        pause
        return
    fi

    echo -e "${GREEN}[*] 自动模式已启动${RESET}"
    echo -e "    网卡: ${CYAN}$NET_IF${RESET}"
    echo -e "    阈值: ${CYAN}${THRESHOLD_G} Gbps ≈ ${THRESHOLD_MBPS} Mbps${RESET}"
    echo -e "    入口IP: ${CYAN}$TARGET${RESET}"
    echo -e "${GRAY}    每 10 秒统计一次入站流量，大于阈值则对该入口IP添加走高仿的策略路由${RESET}"
    echo -e "${GRAY}    Ctrl + C 退出自动模式${RESET}"
    pause

    local PREV_RX CUR_RX DIFF BPS MBPS
    PREV_RX=$(cat /sys/class/net/"$NET_IF"/statistics/rx_bytes)

    while true; do
        sleep 10
        CUR_RX=$(cat /sys/class/net/"$NET_IF"/statistics/rx_bytes)
        DIFF=$((CUR_RX - PREV_RX))
        PREV_RX=$CUR_RX

        BPS=$((DIFF * 8 / 10))
        MBPS=$((BPS / 1000000))

        echo -e "${GRAY}[AUTO] $(date '+%F %T') 最近10秒 ${NET_IF} 入站 ≈ ${MBPS} Mbps${RESET}"

        if [ "$MBPS" -ge "$THRESHOLD_MBPS" ]; then
            echo -e "${GOLD}[AUTO] 触发阈值，已对 ${TARGET} 启用走高仿清洗${RESET}"
            ip rule add to "$TARGET" lookup "$TABLE_NAME" priority 10000 2>/dev/null || true
        fi
    done
}

menu() {
    while true; do
        clear
        echo -e "${GOLD}━━━━━━━━━━ 高仿 DDoS 控制台 ━━━━━━━━━━${RESET}"
        echo -e "${CYAN}${BOLD}             流量清洗面板${RESET}"
        echo -e "${GOLD}────────────────────────────────────${RESET}"
        echo -e "  ${GOLD}1${RESET}）设置会话参数"
        echo -e "  ${GOLD}2${RESET}）建立 / 重建隧道"
        echo -e "  ${GOLD}3${RESET}）手动开启清洗"
        echo -e "  ${GOLD}4${RESET}）手动停止清洗"
        echo -e "  ${GOLD}5${RESET}）自动清洗模式"
        echo -e "  ${GOLD}6${RESET}）查看当前状态"
        echo -e "  ${GOLD}0${RESET}）退出"
        echo -e "${GOLD}────────────────────────────────────${RESET}"
        read -rp "$(echo -e "${CYAN}请选择: ${RESET}")" CH

        case "$CH" in
            1) config_session ;;
            2) init_tunnel ;;
            3) start_clean_manual ;;
            4) stop_clean_manual ;;
            5) auto_mode ;;
            6) show_status ;;
            0) echo -e "${GREEN}已退出${RESET}"; exit 0 ;;
            *) echo -e "${RED}[-] 无效选择${RESET}"; pause ;;
        esac
    done
}

require_root
menu
