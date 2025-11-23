#!/bin/bash
# =====================================================
# UDP 隧道 自动引流助手（入口 / 高仿 通用）
# 逻辑：
# - 使用 socat 的 TUN+UDP 做 L3 隧道
# - 入口机按带宽阈值自动把入口 IP 流量通过隧道打到高仿
# =====================================================

# 颜色
GOLD='\033[38;5;220m'
CYAN='\033[38;5;44m'
GRAY='\033[38;5;245m'
RED='\033[38;5;196m'
GREEN='\033[38;5;82m'
BOLD='\033[1m'
RESET='\033[0m'

# 参数（只在当前进程 / 守护进程里）
ENTRY_IP=""       # 入口 IP（被攻击入口）
GF_IP=""          # 高仿 IP
ROLE=""           # entry / gf
LOCAL_WAN_IP=""   # 本机公网 IP
REMOTE_WAN_IP=""  # 对端公网 IP

TUN_NAME="gf_tun0"
LOCAL_TUN_IP="10.254.0.1"
REMOTE_TUN_IP="10.254.0.2"
UDP_PORT="40000"

TABLE_ID="200"
TABLE_NAME="gf_route"

NET_IF=""         # 对外网卡
THRESHOLD_G="1"  # 默认 1 Gbps

PID_FILE="/var/run/gf_udp_auto_daemon.pid"
TUN_SVC_PID="/var/run/gf_udp_tun.pid"
LOG_FILE="/var/log/gf_udp_auto_daemon.log"

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[-] 请使用 root 权限运行（sudo / su）。${RESET}"
        exit 1
    fi
}

pause() {
    read -rp "$(echo -e "${GRAY}按回车继续${RESET}")" _
}

auto_detect_ip() {
    ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}'
}

config_session() {
    echo -e "${GOLD}━━━━━━━━━━ UDP 隧道 DDoS 控制台 ━━━━━━━━━━${RESET}"
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

    local AUTO_IP
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
        LOCAL_TUN_IP="10.254.0.1"
        REMOTE_TUN_IP="10.254.0.2"
    else
        LOCAL_WAN_IP="$MY_IP"
        REMOTE_WAN_IP="$ENTRY_IP"
        LOCAL_TUN_IP="10.254.0.2"
        REMOTE_TUN_IP="10.254.0.1"
    fi

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
    echo -e "  UDP 端口:     ${CYAN}$UDP_PORT${RESET}"
    echo -e "  路由表:       ${CYAN}$TABLE_ID $TABLE_NAME${RESET}"
    echo -e "  阈值:         ${CYAN}${THRESHOLD_G} Gbps${RESET}"
    echo
    pause
}

check_base() {
    if [ -z "$ENTRY_IP" ] || [ -z "$GF_IP" ] || [ -z "$ROLE" ]; then
        echo -e "${RED}[-] 还没设置会话参数，请先执行菜单 1${RESET}"
        pause
        return 1
    fi
    return 0
}

install_socat_if_needed() {
    if ! command -v socat >/dev/null 2>&1; then
        echo -e "${GRAY}[*] 未检测到 socat，尝试安装...${RESET}"
        if command -v apt >/dev/null 2>&1; then
            apt update -y && apt install -y socat
        elif command -v yum >/dev/null 2>&1; then
            yum install -y socat
        else
            echo -e "${RED}[-] 无法自动安装 socat，请手动安装后重试${RESET}"
            pause
            return 1
        fi
    fi
    return 0
}

start_udp_tunnel() {
    check_base || return
    install_socat_if_needed || return

    # 停掉旧的
    if [ -f "$TUN_SVC_PID" ] && kill -0 "$(cat "$TUN_SVC_PID")" 2>/dev/null; then
        kill "$(cat "$TUN_SVC_PID")" 2>/dev/null
        rm -f "$TUN_SVC_PID"
        sleep 1
    fi

    echo -e "${GRAY}[*] 启动 UDP 隧道（TUN+UDP）${RESET}"

    if [ "$ROLE" = "gf" ]; then
        # 高仿：监听 UDP
        # TUN 名称指定为 gf_tun0，地址为 LOCAL_TUN_IP/30
        nohup socat TUN:"$TUN_NAME",tun-type=tun,iff-up,up,iff-no-pi,addr="$LOCAL_TUN_IP",peer="$REMOTE_TUN_IP"/30 \
              UDP-LISTEN:"$UDP_PORT",fork,reuseaddr >/var/log/gf_udp_tun.log 2>&1 &
    else
        # 入口：主动连高仿
        nohup socat TUN:"$TUN_NAME",tun-type=tun,iff-up,up,iff-no-pi,addr="$LOCAL_TUN_IP",peer="$REMOTE_TUN_IP"/30 \
              UDP:"$REMOTE_WAN_IP":"$UDP_PORT" >/var/log/gf_udp_tun.log 2>&1 &
    fi

    local PID=$!
    echo "$PID" > "$TUN_SVC_PID"

    # 等 TUN 起来
    sleep 2

    # 添加路由表定义
    if ! grep -qE "^[[:space:]]*$TABLE_ID[[:space:]]+$TABLE_NAME" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
    fi

    # 表默认走隧道
    ip route flush table "$TABLE_NAME" 2>/dev/null
    ip route add default dev "$TUN_NAME" table "$TABLE_NAME"

    echo -e "${GREEN}[+] UDP 隧道已启动，TUN=${TUN_NAME}，本机隧道IP=${LOCAL_TUN_IP}${RESET}"
    echo -e "${GRAY}可以相互 ping 隧道 IP 检查连通：${LOCAL_TUN_IP} ↔ ${REMOTE_TUN_IP}${RESET}"
    pause
}

stop_udp_tunnel() {
    echo -e "${GRAY}[*] 停止 UDP 隧道${RESET}"
    if [ -f "$TUN_SVC_PID" ] && kill -0 "$(cat "$TUN_SVC_PID")" 2>/dev/null; then
        kill "$(cat "$TUN_SVC_PID")" 2>/dev/null
        rm -f "$TUN_SVC_PID"
    fi
    ip link set "$TUN_NAME" down 2>/dev/null || true
    ip link del "$TUN_NAME" 2>/dev/null || true
    ip route flush table "$TABLE_NAME" 2>/dev/null
    echo -e "${GREEN}[+] 隧道进程和路由已清理${RESET}"
    pause
}

enable_redirect() {
    local TARGET="$ENTRY_IP"
    ip rule add to "$TARGET" lookup "$TABLE_NAME" priority 10000 2>/dev/null || true
}

disable_redirect() {
    local TARGET="$ENTRY_IP"
    ip rule del to "$TARGET" lookup "$TABLE_NAME" 2>/dev/null || true
}

show_status() {
    echo -e "${GOLD}━━━━━━━━━━ 当前状态 ━━━━━━━━━━${RESET}"
    echo -e "  身份:         ${CYAN}${ROLE:-"(未设置)"}${RESET}"
    echo -e "  入口IP:       ${CYAN}${ENTRY_IP:-"(未设置)"}${RESET}"
    echo -e "  高仿IP:       ${CYAN}${GF_IP:-"(未设置)"}${RESET}"
    echo -e "  本机公网IP:   ${CYAN}${LOCAL_WAN_IP:-"(未设置)"}${RESET}"
    echo -e "  对端公网IP:   ${CYAN}${REMOTE_WAN_IP:-"(未设置)"}${RESET}"
    echo -e "  隧道名称:     ${CYAN}$TUN_NAME${RESET}"
    echo -e "  本机隧道IP:   ${CYAN}${LOCAL_TUN_IP:-"(未设置)"}${RESET}"
    echo -e "  对端隧道IP:   ${CYAN}${REMOTE_TUN_IP:-"(未设置)"}${RESET}"
    echo -e "  UDP 端口:     ${CYAN}${UDP_PORT}${RESET}"
    echo -e "  路由表:       ${CYAN}${TABLE_ID} ${TABLE_NAME}${RESET}"
    echo -e "  监控网卡:     ${CYAN}${NET_IF:-"(未设置)"}${RESET}"
    echo -e "  阈值(Gbps):   ${CYAN}${THRESHOLD_G}${RESET}"
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo -e "  守护进程:     ${GREEN}运行中 (PID $(cat "$PID_FILE"))${RESET}"
    else
        echo -e "  守护进程:     ${RED}未运行${RESET}"
    fi
    if [ -f "$TUN_SVC_PID" ] && kill -0 "$(cat "$TUN_SVC_PID")" 2>/dev/null; then
        echo -e "  UDP 隧道:     ${GREEN}运行中 (PID $(cat "$TUN_SVC_PID"))${RESET}"
    else
        echo -e "  UDP 隧道:     ${RED}未运行${RESET}"
    fi
    echo -e "${GOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    echo -e "${GRAY}[*] ip addr show dev ${TUN_NAME}:${RESET}"
    ip addr show dev "$TUN_NAME" 2>/dev/null || echo "  ${TUN_NAME} 未创建"
    echo
    echo -e "${GRAY}[*] ip rule | grep ${TABLE_NAME}:${RESET}"
    ip rule | grep "$TABLE_NAME" || echo "  没有使用 ${TABLE_NAME} 的规则"
    echo
    echo -e "${GRAY}[*] ip route show table ${TABLE_NAME}:${RESET}"
    ip route show table "$TABLE_NAME" || echo "  路由表 ${TABLE_NAME} 为空"
    echo
    pause
}

auto_loop() {
    local THRESHOLD_MBPS=$((THRESHOLD_G * 1000))
    local PREV_RX CUR_RX DIFF BPS MBPS
    local activated=0
    local below_count=0
    local TARGET="$ENTRY_IP"

    echo "[$(date '+%F %T')] Auto daemon started, iface=$NET_IF, threshold=${THRESHOLD_G}Gbps, target=$TARGET" >> "$LOG_FILE"

    PREV_RX=$(cat /sys/class/net/"$NET_IF"/statistics/rx_bytes)

    while true; do
        sleep 10
        CUR_RX=$(cat /sys/class/net/"$NET_IF"/statistics/rx_bytes)
        DIFF=$((CUR_RX - PREV_RX))
        PREV_RX=$CUR_RX

        BPS=$((DIFF * 8 / 10))
        MBPS=$((BPS / 1000000))

        echo "[$(date '+%F %T')] iface=$NET_IF in=${MBPS}Mbps" >> "$LOG_FILE"

        if [ "$MBPS" -ge "$THRESHOLD_MBPS" ]; then
            if [ "$activated" -eq 0 ]; then
                echo "[$(date '+%F %T')] threshold hit, enable redirect for $TARGET" >> "$LOG_FILE"
                enable_redirect
                activated=1
            fi
            below_count=0
        else
            if [ "$activated" -eq 1 ]; then
                below_count=$((below_count + 1))
                if [ "$below_count" -ge 6 ]; then
                    echo "[$(date '+%F %T')] traffic back to normal, disable redirect for $TARGET" >> "$LOG_FILE"
                    disable_redirect
                    activated=0
                    below_count=0
                fi
            fi
        fi
    done
}

start_daemon() {
    check_base || return

    if [ "$ROLE" != "entry" ]; then
        echo -e "${RED}[-] 自动引流守护进程只需要在入口服务器上运行${RESET}"
        pause
        return
    fi

    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo -e "${GREEN}[+] 守护进程已在运行 (PID $(cat "$PID_FILE"))${RESET}"
        pause
        return
    fi

    if [ -z "$NET_IF" ]; then
        echo -e "${GRAY}当前网卡列表：${RESET}"
        ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno|em)[0-9]+' || true
        read -rp "$(echo -e "${CYAN}对外网卡名: ${RESET}")" NET_IF
    fi

    read -rp "$(echo -e "${CYAN}触发清洗阈值（Gbps，回车默认=${THRESHOLD_G}）: ${RESET}")" TMP_TH
    if [ -n "$TMP_TH" ]; then
        THRESHOLD_G="$TMP_TH"
    fi

    if [ -z "$NET_IF" ]; then
        echo -e "${RED}[-] 网卡未设置${RESET}"
        pause
        return
    fi

    echo -e "${GRAY}[*] 启动自动守护进程，日志：${LOG_FILE}${RESET}"
    ( auto_loop ) >>"$LOG_FILE" 2>&1 &
    local PID=$!
    echo "$PID" > "$PID_FILE"

    echo -e "${GREEN}[+] 守护进程已启动 (PID ${PID})${RESET}"
    pause
}

stop_daemon() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        local PID
        PID=$(cat "$PID_FILE")
        kill "$PID" 2>/dev/null
        rm -f "$PID_FILE"
        echo -e "${GREEN}[+] 守护进程已停止${RESET}"
    else
        echo -e "${GRAY}[*] 当前没有运行中的守护进程${RESET}"
    fi
    pause
}

uninstall_all() {
    echo -e "${GOLD}━━━━━━━━━━ 卸载 / 清理 ━━━━━━━━━━${RESET}"

    stop_daemon
    stop_udp_tunnel

    echo -e "${GRAY}[*] 删除相关策略路由规则...${RESET}"
    if ip rule | grep -q "$TABLE_NAME"; then
        for prio in $(ip rule | awk '/'"$TABLE_NAME"'/ {print $1}'); do
            ip rule del priority "$prio" 2>/dev/null
        done
    fi

    echo -e "${GRAY}[*] 清空路由表 ${TABLE_NAME}...${RESET}"
    ip route flush table "$TABLE_NAME" 2>/dev/null

    if [ -f /etc/iproute2/rt_tables ]; then
        echo -e "${GRAY}[*] 移除 /etc/iproute2/rt_tables 中的标记...${RESET}"
        sed -i "/[[:space:]]$TABLE_ID[[:space:]]$TABLE_NAME/d" /etc/iproute2/rt_tables
    fi

    echo
    echo -e "${GREEN}[+] 已清理隧道、路由表和守护进程${RESET}"
    echo -e "${GRAY}如需删除脚本文件，可执行：rm -f nos_udp_auto.sh${RESET}"
    pause
}

menu() {
    while true; do
        clear
        echo -e "${GOLD}━━━━━━━━━━ UDP 隧道 DDoS 控制台 ━━━━━━━━━━${RESET}"
        echo -e "${CYAN}${BOLD}             自动引流模式${RESET}"
        echo -e "${GOLD}────────────────────────────────────${RESET}"
        echo -e "  ${GOLD}1${RESET}）设置会话参数"
        echo -e "  ${GOLD}2${RESET}）启动 / 停止 UDP 隧道"
        echo -e "  ${GOLD}3${RESET}）启动自动守护 / 停止守护（入口机）"
        echo -e "  ${GOLD}4${RESET}）查看当前状态"
        echo -e "  ${GOLD}5${RESET}）卸载 / 清理"
        echo -e "  ${GOLD}0${RESET}）退出"
        echo -e "${GOLD}────────────────────────────────────${RESET}"
        read -rp "$(echo -e "${CYAN}请选择: ${RESET}")" CH

        case "$CH" in
            1) config_session ;;
            2)
                if [ -f "$TUN_SVC_PID" ] && kill -0 "$(cat "$TUN_SVC_PID")" 2>/dev/null; then
                    stop_udp_tunnel
                else
                    start_udp_tunnel
                fi
                ;;
            3)
                if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
                    stop_daemon
                else
                    start_daemon
                fi
                ;;
            4) show_status ;;
            5) uninstall_all ;;
            0) echo -e "${GREEN}已退出${RESET}"; exit 0 ;;
            *) echo -e "${RED}[-] 无效选择${RESET}"; pause ;;
        esac
    done
}

require_root
menu
