#!/usr/bin/env bash
#
# GRE6 Tunnel Manager (fixed)
# Tunnel GRE-over-IPv6 بین سرور ایران و خارج، با systemd و DNAT پورت‌ها.
#
# Fixes vs modernvps-gre-v6:
#   1) whitelist رنج ایران اختیاری است (دیگر سرور را بلاک اجباری نمی‌کند)
#   2) اگر IPv6 عمومی نباشد، خودکار 6to4 (SIT روی IPv4) می‌سازد بعد GRE6
#   3) بارگذاری ماژول‌های کرنل (ip6_gre / sit)
#   4) تشخیص بهتر IP، تست ping، MTU قابل تنظیم
#
# Must be run as root.
#

set -o pipefail

STATE_DIR="/etc/gre6-tunnel"
STATE_FILE="$STATE_DIR/state.conf"
UP_SCRIPT="$STATE_DIR/gre6-up.sh"
DOWN_SCRIPT="$STATE_DIR/gre6-down.sh"
SERVICE_FILE="/etc/systemd/system/gre6-tunnel.service"
NAT_CHAIN="GRE6_TUNNEL"
IRAN_RANGES_URL="http://81.12.32.210/downloads/iran-ranges-v6.txt"

# Private overlay (inner GRE)
IRAN_TUN_IP="172.16.1.1/30"
KHAREJ_TUN_IP="172.16.1.2/30"
IRAN_TUN_HOST="172.16.1.1"
KHAREJ_TUN_HOST="172.16.1.2"

# Private IPv6 for 6to4 underlay (when native IPv6 is unavailable)
SIT_IRAN_V6="fd00:6t04:a::1/64"
SIT_KHAREJ_V6="fd00:6t04:a::2/64"
SIT_IRAN_HOST="fd00:6t04:a::1"
SIT_KHAREJ_HOST="fd00:6t04:a::2"

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"

print_step()    { echo -e "${COLOR_CYAN}==>${COLOR_RESET} $1"; }
print_success() { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $1"; }
print_error()   { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1"; }
print_warning() { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root."
        exit 1
    fi
}

pause() {
    read -rp "Press Enter to continue..." _
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_deps() {
    local missing=()
    for c in ip iptables systemctl; do
        have_cmd "$c" || missing+=("$c")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        print_error "Missing commands: ${missing[*]}"
        return 1
    fi
    if ! have_cmd python3; then
        print_warning "python3 not found — IPv6 validation will use a simpler check."
    fi
    return 0
}

load_modules() {
    print_step "Loading kernel modules..."
    modprobe ip6_gre 2>/dev/null || modprobe ip6gre 2>/dev/null || true
    modprobe gre 2>/dev/null || true
    modprobe sit 2>/dev/null || true
    modprobe ip_tunnel 2>/dev/null || true
    modprobe ipv6 2>/dev/null || true

    if ! lsmod 2>/dev/null | grep -qE 'ip6_gre|ip6gre'; then
        # Some kernels build ip6gre in (no module); try creating a temp link type probe
        if ! ip link help 2>&1 | grep -qi ip6gre && ! ip tunnel help 2>&1 | grep -qi ip6gre; then
            print_warning "ip6_gre module may be unavailable. Native GRE6 might fail."
        fi
    fi
    print_success "Kernel modules ready (best-effort)."
}

validate_ipv6() {
    local ip="$1"
    if have_cmd python3; then
        python3 -c '
import sys, ipaddress
try:
    ipaddress.IPv6Address(sys.argv[1])
except Exception:
    sys.exit(1)
sys.exit(0)
' "$ip" 2>/dev/null
    else
        [[ "$ip" == *:* ]] && [[ "$ip" != *" "* ]]
    fi
}

validate_ipv4() {
    local ip="$1"
    if have_cmd python3; then
        python3 -c '
import sys, ipaddress
try:
    ipaddress.IPv4Address(sys.argv[1])
except Exception:
    sys.exit(1)
sys.exit(0)
' "$ip" 2>/dev/null
    else
        [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
    fi
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

get_public_ipv6() {
    local ip
    ip=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' \
        | head -1)
    if [[ -n "$ip" && "$ip" == *:* ]]; then
        echo "$ip"
        return 0
    fi

    ip=$(ip -6 addr show scope global 2>/dev/null \
        | awk '/inet6/{print $2}' | cut -d/ -f1 \
        | grep -vE '^(fc|fd|fe80)' | head -1)
    if [[ -n "$ip" && "$ip" == *:* ]]; then
        echo "$ip"
        return 0
    fi

    echo ""
    return 1
}

get_public_ipv4() {
    local ip
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' \
        | head -1)
    if [[ -n "$ip" && "$ip" != *" "* ]]; then
        echo "$ip"
        return 0
    fi

    ip=$(ip -4 addr show scope global 2>/dev/null \
        | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi

    echo ""
    return 1
}

# Soft check only — never hard-blocks setup.
check_iran_whitelist() {
    local ip="$1"
    if ! have_cmd python3; then
        return 2
    fi

    python3 - "$ip" << EOF
import sys, ipaddress, urllib.request

ip = ipaddress.ip_address(sys.argv[1])
url = "${IRAN_RANGES_URL}"

try:
    data = urllib.request.urlopen(url, timeout=5).read().decode().strip().splitlines()
except Exception:
    sys.exit(2)

for line in data:
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        net = ipaddress.ip_network(line, strict=False)
        if ip in net:
            sys.exit(0)
    except Exception:
        continue

sys.exit(1)
EOF
}

validate_port_list() {
    local raw="$1"
    local IFS=','
    local -a parts=($raw)
    local -a clean=()
    local p
    for p in "${parts[@]}"; do
        p="$(echo "$p" | xargs)"
        [ -z "$p" ] && continue
        if ! validate_port "$p"; then
            print_error "Invalid port: $p"
            return 1
        fi
        if [ "$p" -eq 22 ]; then
            print_error "Port 22 (SSH) cannot be forwarded through the tunnel."
            return 1
        fi
        clean+=("$p")
    done
    if [ "${#clean[@]}" -eq 0 ]; then
        print_error "No valid ports entered."
        return 1
    fi
    local joined
    joined=$(IFS=','; echo "${clean[*]}")
    echo "$joined"
    return 0
}

ask_mtu() {
    local mtu
    read -rp "Tunnel MTU [default 1400, try 1280 if ping fails]: " mtu
    mtu="${mtu:-1400}"
    if ! [[ "$mtu" =~ ^[0-9]+$ ]] || [ "$mtu" -lt 576 ] || [ "$mtu" -gt 1500 ]; then
        print_warning "Invalid MTU, using 1400." >&2
        mtu=1400
    fi
    printf '%s\n' "$mtu"
}

choose_underlay() {
    local detected_v6="$1"
    echo "" >&2
    echo "Underlay mode:" >&2
    echo "  1) Native IPv6  (هر دو سرور IPv6 عمومی دارند)" >&2
    echo "  2) 6to4 / SIT  (روی IPv4 عمومی — وقتی IPv6 ندارید یا IPv6 فیلتر است)" >&2
    if [[ -n "$detected_v6" ]]; then
        echo "  3) Auto        (الان IPv6 تشخیص داده شد → Native)" >&2
    else
        echo "  3) Auto        (IPv6 نیست → 6to4)" >&2
    fi
    local choice
    read -rp "Select [1/2/3, default 3]: " choice
    choice="${choice:-3}"
    case "$choice" in
        1) printf '%s\n' "native" ;;
        2) printf '%s\n' "6to4" ;;
        *)
            if [[ -n "$detected_v6" ]]; then
                printf '%s\n' "native"
            else
                printf '%s\n' "6to4"
            fi
            ;;
    esac
}

write_managed_scripts() {
    mkdir -p "$STATE_DIR"

    cat > "$UP_SCRIPT" << 'UPEOF'
#!/usr/bin/env bash
set -e

STATE_FILE="/etc/gre6-tunnel/state.conf"
NAT_CHAIN="GRE6_TUNNEL"

[ -f "$STATE_FILE" ] || exit 0
# shellcheck disable=SC1090
source "$STATE_FILE"

UNDERLAY="${UNDERLAY:-native}"
MTU="${MTU:-1400}"
SIT_MTU="${SIT_MTU:-1480}"

sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

modprobe ip6_gre 2>/dev/null || modprobe ip6gre 2>/dev/null || true
modprobe sit 2>/dev/null || true

# Cleanup GRE6
if ip link show GRE6 >/dev/null 2>&1; then
    ip addr flush dev GRE6 2>/dev/null || true
    ip route flush dev GRE6 2>/dev/null || true
    ip link set GRE6 down 2>/dev/null || true
    ip link delete GRE6 2>/dev/null || true
fi

# Cleanup SIT
if ip link show SIT6 >/dev/null 2>&1; then
    ip -6 addr flush dev SIT6 2>/dev/null || true
    ip link set SIT6 down 2>/dev/null || true
    ip link delete SIT6 2>/dev/null || true
fi

resolve_endpoints() {
    if [ "$UNDERLAY" = "6to4" ]; then
        # Build private IPv6 path over public IPv4 via SIT
        if [ "$MODE" = "iran" ]; then
            ip tunnel add SIT6 mode sit remote "$KHAREJ_IP" local "$IRAN_IP" ttl 255
            ip link set SIT6 mtu "$SIT_MTU"
            ip link set SIT6 up
            ip -6 addr add "$SIT_IRAN_V6" dev SIT6
            LOCAL_V6="$SIT_IRAN_HOST"
            REMOTE_V6="$SIT_KHAREJ_HOST"
        else
            ip tunnel add SIT6 mode sit remote "$IRAN_IP" local "$KHAREJ_IP" ttl 255
            ip link set SIT6 mtu "$SIT_MTU"
            ip link set SIT6 up
            ip -6 addr add "$SIT_KHAREJ_V6" dev SIT6
            LOCAL_V6="$SIT_KHAREJ_HOST"
            REMOTE_V6="$SIT_IRAN_HOST"
        fi
        # Give SIT a moment before GRE6
        sleep 1
    else
        if [ "$MODE" = "iran" ]; then
            LOCAL_V6="$IRAN_IP"
            REMOTE_V6="$KHAREJ_IP"
        else
            LOCAL_V6="$KHAREJ_IP"
            REMOTE_V6="$IRAN_IP"
        fi
    fi
}

resolve_endpoints

if [ "$MODE" = "iran" ]; then
    ip link add name GRE6 type ip6gre local "$LOCAL_V6" remote "$REMOTE_V6"
    ip addr add 172.16.1.1/30 dev GRE6
    ip link set GRE6 mtu "$MTU"
    ip link set GRE6 up

    iptables -t nat -N "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$NAT_CHAIN"
    iptables -t nat -C PREROUTING -j "$NAT_CHAIN" 2>/dev/null || iptables -t nat -A PREROUTING -j "$NAT_CHAIN"

    # MSS clamp helps when PMTUD is broken on some Iranian paths
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
        || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    IFS=',' read -ra PORT_ARR <<< "$PORTS"
    for p in "${PORT_ARR[@]}"; do
        [ -z "$p" ] && continue
        iptables -t nat -A "$NAT_CHAIN" -p tcp --dport "$p" -j DNAT --to-destination 172.16.1.2:"$p"
        iptables -t nat -A "$NAT_CHAIN" -p udp --dport "$p" -j DNAT --to-destination 172.16.1.2:"$p"
    done

    iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -j MASQUERADE

elif [ "$MODE" = "kharej" ]; then
    ip link add name GRE6 type ip6gre local "$LOCAL_V6" remote "$REMOTE_V6"
    ip addr add 172.16.1.2/30 dev GRE6
    ip link set GRE6 mtu "$MTU"
    ip link set GRE6 up

    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
        || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
fi

exit 0
UPEOF

    cat > "$DOWN_SCRIPT" << 'DOWNEOF'
#!/usr/bin/env bash
STATE_FILE="/etc/gre6-tunnel/state.conf"
NAT_CHAIN="GRE6_TUNNEL"

[ -f "$STATE_FILE" ] && source "$STATE_FILE"

if [ "$MODE" = "iran" ]; then
    iptables -t nat -D PREROUTING -j "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null || true
fi

iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

if ip link show GRE6 >/dev/null 2>&1; then
    ip addr flush dev GRE6 2>/dev/null || true
    ip route flush dev GRE6 2>/dev/null || true
    ip link set GRE6 down 2>/dev/null || true
    ip link delete GRE6 2>/dev/null || true
fi

if ip link show SIT6 >/dev/null 2>&1; then
    ip -6 addr flush dev SIT6 2>/dev/null || true
    ip link set SIT6 down 2>/dev/null || true
    ip link delete SIT6 2>/dev/null || true
fi

exit 0
DOWNEOF

    chmod +x "$UP_SCRIPT" "$DOWN_SCRIPT"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=GRE6 Tunnel (GRE over IPv6 / optional 6to4)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${UP_SCRIPT}
ExecStop=${DOWN_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-networkd-wait-online.service'; then
        systemctl enable systemd-networkd-wait-online.service >/dev/null 2>&1 || true
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q '^NetworkManager-wait-online.service'; then
        systemctl enable NetworkManager-wait-online.service >/dev/null 2>&1 || true
    fi
}

test_tunnel() {
    local peer="$1"
    print_step "Testing tunnel: ping $peer ..."
    if ping -c 3 -W 2 "$peer" >/dev/null 2>&1; then
        print_success "Ping OK — tunnel is carrying traffic."
        return 0
    fi
    print_warning "Ping FAILED. Interface may be UP but packets are dropped."
    echo "  Tips:"
    echo "  - مطمئن شوید سمت مقابل هم کانفیگ شده"
    echo "  - اگر Native IPv6 جواب نداد، دوباره با حالت 6to4 نصب کنید"
    echo "  - MTU را روی 1280 بگذارید"
    echo "  - بعضی دیتاسنترها GRE/ip6gre را فیلتر می‌کنند → WireGuard یا GRE-over-UDP"
    return 1
}

apply_tunnel() {
    local peer_host="$1"
    systemctl enable gre6-tunnel.service >/dev/null 2>&1
    systemctl restart gre6-tunnel.service

    sleep 1
    if systemctl is-active --quiet gre6-tunnel.service; then
        print_success "GRE6 tunnel applied and running."
        ip -br link show GRE6 2>/dev/null || true
        ip -br addr show GRE6 2>/dev/null || true
        [ -n "$peer_host" ] && test_tunnel "$peer_host"
    else
        print_error "GRE6 tunnel failed to apply. Check: journalctl -u gre6-tunnel.service -xe"
        journalctl -u gre6-tunnel.service -n 30 --no-pager 2>/dev/null || true
    fi
}

configure_iran() {
    ensure_deps || { pause; return; }
    load_modules

    local det_v6 det_v4
    det_v6=$(get_public_ipv6 || true)
    det_v4=$(get_public_ipv4 || true)
    echo "Detected IPv6: ${det_v6:-Not Detected}"
    echo "Detected IPv4: ${det_v4:-Not Detected}"

    if [[ -n "$det_v6" ]]; then
        print_step "Optional Iran IPv6 range check (non-blocking)..."
        check_iran_whitelist "$det_v6"
        case $? in
            0) print_success "IP appears in Iran ranges list." ;;
            1) print_warning "IP NOT in Iran ranges list — continuing anyway (fixed)." ;;
            *) print_warning "Could not fetch ranges list — continuing." ;;
        esac
    fi

    local underlay
    underlay=$(choose_underlay "$det_v6")
    print_step "Selected underlay: $underlay"

    local iran_ip kharej_ip inbound_ports clean_ports mtu
    if [ "$underlay" = "native" ]; then
        read -rp "Enter Iran Server Public IPv6 [${det_v6}]: " iran_ip
        iran_ip="${iran_ip:-$det_v6}"
        if ! validate_ipv6 "$iran_ip"; then
            print_error "Invalid IPv6 address."
            pause; return
        fi
        read -rp "Enter Kharej Server Public IPv6: " kharej_ip
        if ! validate_ipv6 "$kharej_ip"; then
            print_error "Invalid IPv6 address."
            pause; return
        fi
    else
        read -rp "Enter Iran Server Public IPv4 [${det_v4}]: " iran_ip
        iran_ip="${iran_ip:-$det_v4}"
        if ! validate_ipv4 "$iran_ip"; then
            print_error "Invalid IPv4 address."
            pause; return
        fi
        read -rp "Enter Kharej Server Public IPv4: " kharej_ip
        if ! validate_ipv4 "$kharej_ip"; then
            print_error "Invalid IPv4 address."
            pause; return
        fi
    fi

    read -rp "Inbound Ports (e.g. 443,2070,2080): " inbound_ports
    if ! clean_ports=$(validate_port_list "$inbound_ports"); then
        pause; return
    fi
    mtu=$(ask_mtu)

    mkdir -p "$STATE_DIR"
    cat > "$STATE_FILE" << EOF
MODE=iran
UNDERLAY=${underlay}
IRAN_IP=${iran_ip}
KHAREJ_IP=${kharej_ip}
PORTS=${clean_ports}
MTU=${mtu}
SIT_MTU=1480
SIT_IRAN_V6=${SIT_IRAN_V6}
SIT_KHAREJ_V6=${SIT_KHAREJ_V6}
SIT_IRAN_HOST=${SIT_IRAN_HOST}
SIT_KHAREJ_HOST=${SIT_KHAREJ_HOST}
EOF

    write_managed_scripts
    apply_tunnel "$KHAREJ_TUN_HOST"
    pause
}

configure_kharej() {
    ensure_deps || { pause; return; }
    load_modules

    local det_v6 det_v4
    det_v6=$(get_public_ipv6 || true)
    det_v4=$(get_public_ipv4 || true)
    echo "Detected IPv6: ${det_v6:-Not Detected}"
    echo "Detected IPv4: ${det_v4:-Not Detected}"

    local underlay
    underlay=$(choose_underlay "$det_v6")
    print_step "Selected underlay: $underlay"
    print_warning "UNDERLAY must match Iran side (native یا 6to4 یکسان)."

    local iran_ip kharej_ip mtu
    if [ "$underlay" = "native" ]; then
        read -rp "Enter Kharej Server Public IPv6 [${det_v6}]: " kharej_ip
        kharej_ip="${kharej_ip:-$det_v6}"
        if ! validate_ipv6 "$kharej_ip"; then
            print_error "Invalid IPv6 address."
            pause; return
        fi
        read -rp "Enter Iran Server Public IPv6: " iran_ip
        if ! validate_ipv6 "$iran_ip"; then
            print_error "Invalid IPv6 address."
            pause; return
        fi
    else
        read -rp "Enter Kharej Server Public IPv4 [${det_v4}]: " kharej_ip
        kharej_ip="${kharej_ip:-$det_v4}"
        if ! validate_ipv4 "$kharej_ip"; then
            print_error "Invalid IPv4 address."
            pause; return
        fi
        read -rp "Enter Iran Server Public IPv4: " iran_ip
        if ! validate_ipv4 "$iran_ip"; then
            print_error "Invalid IPv4 address."
            pause; return
        fi
    fi
    mtu=$(ask_mtu)

    mkdir -p "$STATE_DIR"
    cat > "$STATE_FILE" << EOF
MODE=kharej
UNDERLAY=${underlay}
IRAN_IP=${iran_ip}
KHAREJ_IP=${kharej_ip}
PORTS=
MTU=${mtu}
SIT_MTU=1480
SIT_IRAN_V6=${SIT_IRAN_V6}
SIT_KHAREJ_V6=${SIT_KHAREJ_V6}
SIT_IRAN_HOST=${SIT_IRAN_HOST}
SIT_KHAREJ_HOST=${SIT_KHAREJ_HOST}
EOF

    write_managed_scripts
    apply_tunnel "$IRAN_TUN_HOST"
    pause
}

remove_tunnel() {
    if [ ! -f "$SERVICE_FILE" ] && [ ! -d "$STATE_DIR" ]; then
        print_warning "No GRE6 tunnel is configured."
        pause; return
    fi

    print_step "Stopping and disabling the tunnel..."
    systemctl stop gre6-tunnel.service >/dev/null 2>&1 || true
    systemctl disable gre6-tunnel.service >/dev/null 2>&1 || true

    if [ -x "$DOWN_SCRIPT" ]; then
        "$DOWN_SCRIPT" || true
    fi

    rm -f "$SERVICE_FILE"
    rm -rf "$STATE_DIR"
    systemctl daemon-reload

    print_success "GRE6 tunnel removed."
    pause
}

status_tunnel() {
    echo "=== Service ==="
    systemctl status gre6-tunnel.service --no-pager 2>/dev/null || echo "(not installed)"
    echo ""
    echo "=== State ==="
    [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "(no state)"
    echo ""
    echo "=== Interfaces ==="
    ip -br link show GRE6 2>/dev/null || echo "GRE6: down/missing"
    ip -br link show SIT6 2>/dev/null || true
    ip addr show GRE6 2>/dev/null || true
    pause
}

main_menu() {
    while true; do
        clear
        local v6 v4
        v6=$(get_public_ipv6 || true)
        v4=$(get_public_ipv4 || true)
        echo "Detected VPS IPv6: ${v6:-Not Detected}"
        echo "Detected VPS IPv4: ${v4:-Not Detected}"
        echo "=============================================="
        echo "   GRE6 Tunnel Manager (fixed / all ranges)"
        echo "=============================================="
        echo "1) Configure Iran Server"
        echo "2) Configure Kharej Server"
        echo "3) Remove Tunnel"
        echo "4) Status / Diagnose"
        echo "0) Exit"
        echo "=============================================="
        echo "Tip: اگر Native IPv6 کار نکرد → حالت 6to4 انتخاب کنید"
        echo "=============================================="
        read -rp "Select an option: " opt
        case "$opt" in
            1) configure_iran ;;
            2) configure_kharej ;;
            3) remove_tunnel ;;
            4) status_tunnel ;;
            0) exit 0 ;;
            *) print_warning "Invalid option."; pause ;;
        esac
    done
}

require_root
main_menu
