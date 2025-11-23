#!/bin/bash
# =====================================================
# 高仿一键助手（单脚本版）
# 功能：
#   - 配置：入口IP / 高仿IP / 本机身份 / 网卡 / 阈值(Gbps)
#   - 自动生成隧道IP & 路由表
#   - 一键建立/重建 GRE 隧道
#   - 手动：让某个入口IP 走高仿清洗 / 停止清洗
#   - 自动：按网卡流量阈值(Gbps)把入口IP打到高仿
#
# 特点：
#   - 不写任何配置文件，不在脚本里暴露真实IP
#   - 多个入口配一个高仿：每台入口服务器都用这个脚本即可
# =====================================================

# 会话变量（只在脚本进程里存在）
ENTRY_IP=""       # 入口IP（被打的那个公网IP）
GF_IP=""          # 高仿IP（高防服务器公网IP）
ROLE=""           # self role: entry / gf
LOCAL_WAN_IP=""   # 本机公网IP
REMOTE_WAN_IP=""  # 对端公网IP

TUN_NAME="gf_tun0"
LOCAL_TUN_IP=""
REMOTE_TUN_IP=""

TABLE_ID="200"
TABLE_NAME="gf_route"

NET_IF=""         # 用来统计带宽的网卡
THRESHOLD_G=""    # 触发清洗的阈值（Gbps，整数）

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "[-] 请用 root 权限运行此脚本（sudo / root）"
        exit 1
    fi
}

pause() {
    read -rp "按回车继续..." _
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

# 根据 ENTRY_IP / GF_IP 自动生成一条 10.253.x.y/30 的隧道网段
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

    # 随机一点但可复现：同一对 入口IP/高仿IP 算出同一隧道网段
    local x=$(( (c + d*3) % 250 ))   # 0-249
    local y=$(( (d*7) % 252 ))       # 0,4,8,...252 (/30 对齐)

    local net_int=$(( (10<<24) + (253<<16) + (x<<8) + y ))
    local host1_int=$((net_int + 1))
    local host2_int=$((net_int + 2))

    local host1_ip host2_ip
    host1_ip=$(int2ip "$host1_int")
    host2_ip=$(int2ip "$host2_int")

    # 规则：较小的公网IP 对应隧道 host1，大的对应 host2
    # ENTRY_IP / GF_IP 谁小谁拿 host1，这样两边脚本结果永远一致
    local intEntry intGf
    intEntry=$(ip2int "$ENTRY_IP")
    intGf=$(ip2int "$GF_IP")

    if [ "$intEntry" -le "$intGf" ]; then
        # ENTRY = host1, GF = host2
        if [ "$ROLE" = "entry" ]; then
            LOCAL_TUN_IP="$host1_ip"
            REMOTE_TUN_IP="$host2_ip"
        else
            LOCAL_TUN_IP="$host2_ip"
            REMOTE_TUN_IP="$host1_ip"
        fi
    else
        # ENTRY = host2, GF = host1
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
    echo "============== 本次会话参数 =============="

    echo "本机身份？"
    echo "  1) 入口服务器（对外那台，被打）"
    echo "  2) 高仿服务器（高防那台，负责清洗）"
    read -rp "请选择 1 或 2: " r
    case "$r" in
        1) ROLE="entry" ;;
        2) ROLE="gf" ;;
        *) echo "[-] 选择无效"; pause; return ;;
    esac

    # 入口IP
    read -rp "入口IP（被攻击的那个公网IP）: " ENTRY_IP
    # 高仿IP
    read -rp "高仿IP（高防服务器公网IP）: " GF_IP

    if [ -z "$ENTRY_IP" ] || [ -z "$GF_IP" ]; then
        echo "[-] 入口IP / 高仿IP 不能为空。"
        pause
        return
    fi

    # 本机公网IP（自动探测 + 手动确认）
    AUTO_IP=$(auto_detect_ip)
    if [ -n "$AUTO_IP" ]; then
        echo "自动检测到本机出网IP：$AUTO_IP"
        read -rp "本机公网IP（回车使用自动检测值）: " MY_IP
        MY_IP=${MY_IP:-$AUTO_IP}
    else
        read -rp "本机公网IP: " MY_IP
    fi

    if [ "$ROLE" = "entry" ]; then
        LOCAL_WAN_IP="$MY_IP"
        REMOTE_WAN_IP="$GF_IP"
    else
        LOCAL_WAN_IP="$MY_IP"
        REMOTE_WAN_IP="$ENTRY_IP"
    fi

    # 自动算隧道IP
    calc_tunnel_ips

    echo
    echo "[自动生成的隧道配置]"
    echo "  本机身份:       $ROLE"
    echo "  入口IP:         $ENTRY_IP"
    echo "  高仿IP:         $GF_IP"
    echo "  本机公网IP:     $LOCAL_WAN_IP"
    echo "  对端公网IP:     $REMOTE_WAN_IP"
    echo "  隧道名称:       $TUN_NAME"
    echo "  本机隧道IP:     $LOCAL_TUN_IP"
    echo "  对端隧道IP:     $REMOTE_TUN_IP"
    echo "  策略路由表:     $TABLE_ID $TABLE_NAME"
    echo "=========================================="
    pause
}

check_base() {
    if [ -z "$ENTRY_IP" ] || [ -z "$GF_IP" ] || [ -z "$ROLE" ]; then
        echo "[-] 还没配置会话参数，请先用菜单 1 设置入口IP/高仿IP/本机身份。"
        pause
        return 1
    fi
    if [ -z "$LOCAL_WAN_IP" ] || [ -z "$REMOTE_WAN_IP" ] || [ -z "$LOCAL_TUN_IP" ] || [ -z "$REMOTE_TUN_IP" ]; then
        echo "[-] 隧道IP/本机IP未就绪，请重新执行菜单 1。"
        pause
        return 1
    fi
    return 0
}

init_tunnel() {
    check_base || return

    echo "[*] 加载 GRE 模块..."
    modprobe ip_gre 2>/dev/null || true

    echo "[*] 删除可能存在的旧隧道: $TUN_NAME"
    ip tunnel del "$TUN_NAME" 2>/dev/null

    echo "[*] 使用本机IP=$LOCAL_WAN_IP，对端IP=$REMOTE_WAN_IP 创建隧道 $TUN_NAME"
    ip tunnel add "$TUN_NAME" mode gre local "$LOCAL_WAN_IP" remote "$REMOTE_WAN_IP" ttl 255

    echo "[*] 配置本机隧道IP: $LOCAL_TUN_IP/30"
    ip addr flush dev "$TUN_NAME" 2>/dev/null
    ip addr add "$LOCAL_TUN_IP"/30 dev "$TUN_NAME"

    echo "[*] 启用隧道网卡"
    ip link set "$TUN_NAME" up

    echo "[*] 检查/添加路由表：$TABLE_ID $TABLE_NAME"
    if ! grep -qE "^[[:space:]]*$TABLE_ID[[:space:]]+$TABLE_NAME" /etc/iproute2/rt_tables; then
        echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
    fi

    echo "[*] 让 $TABLE_NAME 表默认走隧道"
    ip route flush table "$TABLE_NAME" 2>/dev/null
    ip route add default dev "$TUN_NAME" table "$TABLE_NAME"

    echo
    echo "[+] 隧道已初始化。"
    echo "[*] 入口机和高仿机都要各跑一次菜单 1 和菜单 2，"
    echo "    然后可以互相 ping 对端隧道IP 测试："
    echo "      本机隧道IP: $LOCAL_TUN_IP"
    echo "      对端隧道IP: $REMOTE_TUN_IP"
    pause
}

start_clean_manual() {
    check_base || return

    read -rp "要让哪个【入口IP】走高仿清洗？(回车默认=$ENTRY_IP): " TARGET
    TARGET=${TARGET:-$ENTRY_IP}

    if [ -z "$TARGET" ]; then
        echo "[-] 入口IP不能为空。"
        pause
        return
    fi

    echo "[*] 给 $TARGET 添加策略路由：走表 $TABLE_NAME → 隧道 → 高仿"
    ip rule add to "$TARGET" lookup "$TABLE_NAME" priority 10000 2>/dev/null || true

    echo "[+] 已开启：$TARGET 流量会通过隧道 $TUN_NAME → $GF_IP 清洗。"
    pause
}

stop_clean_manual() {
    check_base || return

    read -rp "要停止清洗的【入口IP】(回车默认=$ENTRY_IP): " TARGET
    TARGET=${TARGET:-$ENTRY_IP}

    if [ -z "$TARGET" ]; then
        echo "[-] 入口IP不能为空。"
        pause
        return
    fi

    echo "[*] 删除 $TARGET 的策略路由规则..."
    ip rule del to "$TARGET" lookup "$TABLE_NAME" 2>/dev/null || true

    echo "[+] 已停止：$TARGET 不再强制走高仿。"
    pause
}

show_status() {
    echo "============== 当前会话状态 =============="
    echo "  身份:           ${ROLE:-"(未设置)"}"
    echo "  入口IP:         ${ENTRY_IP:-"(未设置)"}"
    echo "  高仿IP:         ${GF_IP:-"(未设置)"}"
    echo "  本机公网IP:     ${LOCAL_WAN_IP:-"(未设置)"}"
    echo "  对端公网IP:     ${REMOTE_WAN_IP:-"(未设置)"}"
    echo "  隧道名称:       $TUN_NAME"
    echo "  本机隧道IP:     ${LOCAL_TUN_IP:-"(未生成)"}"
    echo "  对端隧道IP:     ${REMOTE_TUN_IP:-"(未生成)"}"
    echo "  路由表:         $TABLE_ID $TABLE_NAME"
    echo "  监控网卡:       ${NET_IF:-"(未设置)"}"
    echo "  阈值(Gbps):     ${THRESHOLD_G:-"(未设置)"}"
    echo "=========================================="
    echo

    echo "[*] ip tunnel show:"
    ip tunnel show

    echo
    echo "[*] ip addr show dev $TUN_NAME:"
    ip addr show dev "$TUN_NAME" 2>/dev/null || echo "  设备 $TUN_NAME 暂未创建"

    echo
    echo "[*] ip rule | grep $TABLE_NAME:"
    ip rule | grep "$TABLE_NAME" || echo "  未找到使用 $TABLE_NAME 的规则"

    echo
    echo "[*] ip route show table $TABLE_NAME:"
    ip route show table "$TABLE_NAME" || echo "  路由表 $TABLE_NAME 暂为空"
    echo
    pause
}

auto_mode() {
    check_base || return

    if [ -z "$NET_IF" ]; then
        echo "当前可用网卡："
        ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno|em)[0-9]+' || true
        read -rp "用于对外的网卡名（例如 eth0 / ens33）: " NET_IF
    fi

    if [ -z "$THRESHOLD_G" ]; then
        read -rp "配置多少 Gbps 时开始把入口IP打到高仿？(整数，例如 1 表示 1Gbps): " THRESHOLD_G
    fi

    if [ -z "$NET_IF" ] || [ -z "$THRESHOLD_G" ]; then
        echo "[-] 网卡 / 阈值 未设置完整。"
        pause
        return
    fi

    local THRESHOLD_MBPS=$((THRESHOLD_G * 1000))

    read -rp "自动模式下要监控哪个入口IP？(回车默认=$ENTRY_IP): " TARGET
    TARGET=${TARGET:-$ENTRY_IP}

    if [ -z "$TARGET" ]; then
        echo "[-] 入口IP不能为空。"
        pause
        return
    fi

    echo "[*] 自动模式启动："
    echo "    网卡：$NET_IF"
    echo "    阈值：${THRESHOLD_G} Gbps ≈ ${THRESHOLD_MBPS} Mbps"
    echo "    被保护入口IP：$TARGET"
    echo "    每 10 秒采样一次入站带宽，大于阈值则给 $TARGET 添加走高仿的策略路由。"
    echo "    (Ctrl + C 可退出自动模式)"
    pause

    local PREV_RX CUR_RX DIFF BPS MBPS
    PREV_RX=$(cat /sys/class/net/"$NET_IF"/statistics/rx_bytes)

    while true; do
        sleep 10
        CUR_RX=$(cat /sys/class/net/"$NET_IF"/statistics/rx_bytes)
        DIFF=$((CUR_RX - PREV_RX))
        PREV_RX=$CUR_RX

        BPS=$((DIFF * 8 / 10))          # 10秒内平均bit/s
        MBPS=$((BPS / 1000000))

        echo "[AUTO] $(date '+%F %T') 最近10秒 $NET_IF 入站约 ${MBPS} Mbps"

        if [ "$MBPS" -ge "$THRESHOLD_MBPS" ]; then
            echo "[AUTO] 触发阈值(${THRESHOLD_MBPS}Mbps)，对 $TARGET 启用走高仿清洗..."
            ip rule add to "$TARGET" lookup "$TABLE_NAME" priority 10000 2>/dev/null || true
        fi
    done
}

menu() {
    while true; do
        clear
        echo "=========================================="
        echo "           高仿一键助手（单脚本）         "
        echo "=========================================="
        echo "1) 设置本次会话参数（入口IP / 高仿IP / 身份）"
        echo "2) 建立/重建隧道（本机 ↔ 对端）"
        echo "3) 手动：让某个入口IP 走高仿清洗"
        echo "4) 手动：停止某个入口IP 的高仿清洗"
        echo "5) 自动模式：按网卡流量(Gbps)自动打到高仿"
        echo "6) 查看当前隧道 / 路由 / 参数状态"
        echo "0) 退出（所有参数只在本次运行中有效）"
        echo "------------------------------------------"
        read -rp "请选择: " CH

        case "$CH" in
            1) config_session ;;
            2) init_tunnel ;;
            3) start_clean_manual ;;
            4) stop_clean_manual ;;
            5) auto_mode ;;
            6) show_status ;;
            0) exit 0 ;;
            *) echo "无效选择"; pause ;;
        esac
    done
}

require_root
menu
