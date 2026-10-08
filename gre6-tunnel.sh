#!/usr/bin/env bash
#
# Universal Iran <-> Kharej tunnel
# Default: GRE-in-UDP (FOU) over public IPv4 — works on most hosts that block raw GRE/GRE6.
# Fallback: WireGuard (if FOU modules missing).
# Optional: native GRE6 / 6to4 for rare cases.
#
# Same UX as modernvps-gre-v6: Iran DNAT selected ports to Kharej overlay IP.
# Must run as root on BOTH servers (same TRANSPORT + same FOU/WG port).
#

set -o pipefail

STATE_DIR="/etc/gre6-tunnel"
STATE_FILE="$STATE_DIR/state.conf"
UP_SCRIPT="$STATE_DIR/gre6-up.sh"
DOWN_SCRIPT="$STATE_DIR/gre6-down.sh"
SERVICE_FILE="/etc/systemd/system/gre6-tunnel.service"
NAT_CHAIN="GRE6_TUNNEL"
WG_CONF="/etc/wireguard/gre6tun.conf"

IRAN_TUN_HOST="172.16.1.1"
KHAREJ_TUN_HOST="172.16.1.2"
DEFAULT_FOU_PORT="5555"
DEFAULT_WG_PORT="51820"
DEFAULT_MTU_FOU="1400"
DEFAULT_MTU_WG="1280"
DEFAULT_MTU_GRE6="1400"

SIT_IRAN_V6="fd00:6404:a::1/64"
SIT_KHAREJ_V6="fd00:6404:a::2/64"
SIT_IRAN_HOST="fd00:6404:a::1"
SIT_KHAREJ_HOST="fd00:6404:a::2"

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

pause() { read -rp "Press Enter to continue..." _; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_deps() {
    local missing=()
    for c in ip iptables systemctl; do
        have_cmd "$c" || missing+=("$c")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        print_error "Missing: ${missing[*]}"
        return 1
    fi
    return 0
}

validate_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    if have_cmd python3; then
        python3 -c 'import sys,ipaddress; ipaddress.IPv4Address(sys.argv[1])' "$ip" 2>/dev/null
    else
        return 0
    fi
}

validate_ipv6() {
    local ip="$1"
    [[ "$ip" == *:* ]] || return 1
    if have_cmd python3; then
        python3 -c 'import sys,ipaddress; ipaddress.IPv6Address(sys.argv[1])' "$ip" 2>/dev/null
    else
        return 0
    fi
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

get_public_ipv4() {
    local ip
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
    if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
    ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    [[ -n "$ip" ]] && echo "$ip" && return 0
    echo ""; return 1
}

get_public_ipv6() {
    local ip
    ip=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
    if [[ -n "$ip" && "$ip" == *:* ]]; then echo "$ip"; return 0; fi
    ip=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/{print $2}' | cut -d/ -f1 | grep -vE '^(fc|fd|fe80)' | head -1)
    [[ -n "$ip" ]] && echo "$ip" && return 0
    echo ""; return 1
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
            print_error "Invalid port: $p" >&2
            return 1
        fi
        if [ "$p" -eq 22 ]; then
            print_error "Port 22 (SSH) cannot be forwarded." >&2
            return 1
        fi
        clean+=("$p")
    done
    if [ "${#clean[@]}" -eq 0 ]; then
        print_error "No valid ports." >&2
        return 1
    fi
    (IFS=','; echo "${clean[*]}")
}

fou_available() {
    modprobe fou 2>/dev/null || true
    modprobe ip_gre 2>/dev/null || true
    # FOU support: ip fou help exists and fou module or built-in
    ip fou help >/dev/null 2>&1 || return 1
    return 0
}

wg_available() {
    modprobe wireguard 2>/dev/null || true
    have_cmd wg && have_cmd wg-quick && return 0
    return 1
}

try_install_wireguard() {
    print_step "Trying to install wireguard-tools..."
    if have_cmd apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard wireguard-tools >/dev/null 2>&1 || true
    elif have_cmd yum; then
        yum install -y wireguard-tools >/dev/null 2>&1 || true
    elif have_cmd dnf; then
        dnf install -y wireguard-tools >/dev/null 2>&1 || true
    fi
    wg_available
}

pick_transport() {
    echo "" >&2
    echo "Transport (هر دو سرور باید یکی باشد):" >&2
    echo "  1) FOU  — GRE داخل UDP روی IPv4  [پیشنهادی / روی بیشتر سرورها کار می‌کند]" >&2
    echo "  2) WG   — WireGuard UDP           [اگر FOU نبود]" >&2
    echo "  3) GRE6 — GRE روی IPv6 عمومی      [فقط اگر IPv6 دو طرف به هم می‌رسد]" >&2
    echo "  4) 6to4 — SIT روی IPv4 + GRE6     [اغلب فیلتر می‌شود]" >&2
    echo "  5) Auto — FOU، وگرنه WireGuard" >&2
    local c
    read -rp "Select [default 5]: " c
    c="${c:-5}"
    case "$c" in
        1) printf '%s\n' "fou" ;;
        2) printf '%s\n' "wg" ;;
        3) printf '%s\n' "gre6" ;;
        4) printf '%s\n' "6to4" ;;
        *)
            if fou_available; then
                printf '%s\n' "fou"
            elif try_install_wireguard; then
                printf '%s\n' "wg"
            else
                print_error "Neither FOU nor WireGuard available." >&2
                return 1
            fi
            ;;
    esac
}

ask_mtu() {
    local def="$1"
    local mtu
    read -rp "MTU [default ${def}]: " mtu
    mtu="${mtu:-$def}"
    if ! [[ "$mtu" =~ ^[0-9]+$ ]] || [ "$mtu" -lt 576 ] || [ "$mtu" -gt 1500 ]; then
        print_warning "Invalid MTU, using ${def}." >&2
        mtu="$def"
    fi
    printf '%s\n' "$mtu"
}

open_firewall_udp() {
    local port="$1" peer="$2"
    iptables -C INPUT -p udp --dport "$port" -s "$peer" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p udp --dport "$port" -s "$peer" -j ACCEPT 2>/dev/null || true
    if have_cmd ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        ufw allow from "$peer" to any port "$port" proto udp >/dev/null 2>&1 || true
    fi
}

write_managed_scripts() {
    mkdir -p "$STATE_DIR"

    cat > "$UP_SCRIPT" << 'UPEOF'
#!/usr/bin/env bash
STATE_FILE="/etc/gre6-tunnel/state.conf"
NAT_CHAIN="GRE6_TUNNEL"
WG_CONF="/etc/wireguard/gre6tun.conf"

[ -f "$STATE_FILE" ] || exit 0
# shellcheck disable=SC1090
source "$STATE_FILE"

TRANSPORT="${TRANSPORT:-fou}"
MTU="${MTU:-1400}"
FOU_PORT="${FOU_PORT:-5555}"
WG_PORT="${WG_PORT:-51820}"
GRE_KEY="${GRE_KEY:-1001}"
SIT_MTU="${SIT_MTU:-1480}"
SIT_IRAN_V6="${SIT_IRAN_V6:-fd00:6404:a::1/64}"
SIT_KHAREJ_V6="${SIT_KHAREJ_V6:-fd00:6404:a::2/64}"
SIT_IRAN_HOST="${SIT_IRAN_HOST:-fd00:6404:a::1}"
SIT_KHAREJ_HOST="${SIT_KHAREJ_HOST:-fd00:6404:a::2}"

sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
# Avoid asymmetric path drops on some VPS
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

cleanup_ifaces() {
    if ip link show GRE6 >/dev/null 2>&1; then
        ip addr flush dev GRE6 2>/dev/null || true
        ip link set GRE6 down 2>/dev/null || true
        ip link delete GRE6 2>/dev/null || true
    fi
    if ip link show SIT6 >/dev/null 2>&1; then
        ip -6 addr flush dev SIT6 2>/dev/null || true
        ip link set SIT6 down 2>/dev/null || true
        ip link delete SIT6 2>/dev/null || true
    fi
    if [ -f "$WG_CONF" ] && command -v wg-quick >/dev/null 2>&1; then
        wg-quick down gre6tun >/dev/null 2>&1 || true
    fi
    # Remove our FOU listener if present
    if [ -n "${FOU_PORT:-}" ]; then
        ip fou del port "$FOU_PORT" 2>/dev/null || true
    fi
}

open_udp() {
    local port="$1" peer="$2"
    iptables -C INPUT -p udp --dport "$port" -s "$peer" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p udp --dport "$port" -s "$peer" -j ACCEPT 2>/dev/null || true
}

setup_forward_mss() {
    local dev="$1"
    iptables -C FORWARD -i "$dev" -j ACCEPT 2>/dev/null || iptables -I FORWARD -i "$dev" -j ACCEPT 2>/dev/null || true
    iptables -C FORWARD -o "$dev" -j ACCEPT 2>/dev/null || iptables -I FORWARD -o "$dev" -j ACCEPT 2>/dev/null || true
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
        || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}

setup_iran_nat() {
    iptables -t nat -N "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -C PREROUTING -j "$NAT_CHAIN" 2>/dev/null || iptables -t nat -A PREROUTING -j "$NAT_CHAIN" || true

    IFS=',' read -ra PORT_ARR <<< "${PORTS:-}"
    for p in "${PORT_ARR[@]}"; do
        [ -z "$p" ] && continue
        iptables -t nat -A "$NAT_CHAIN" -p tcp --dport "$p" -j DNAT --to-destination 172.16.1.2:"$p" || true
        iptables -t nat -A "$NAT_CHAIN" -p udp --dport "$p" -j DNAT --to-destination 172.16.1.2:"$p" || true
    done
    iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -j MASQUERADE || true
}

cleanup_ifaces
modprobe fou 2>/dev/null || true
modprobe ip_gre 2>/dev/null || true
modprobe gre 2>/dev/null || true
modprobe ip6_gre 2>/dev/null || modprobe ip6gre 2>/dev/null || true
modprobe sit 2>/dev/null || true
modprobe wireguard 2>/dev/null || true

DEV="GRE6"

case "$TRANSPORT" in
    fou)
        if [ "$MODE" = "iran" ]; then
            LOCAL_PUB="$IRAN_IP"
            REMOTE_PUB="$KHAREJ_IP"
            TUN_ADDR="172.16.1.1/30"
        else
            LOCAL_PUB="$KHAREJ_IP"
            REMOTE_PUB="$IRAN_IP"
            TUN_ADDR="172.16.1.2/30"
        fi
        open_udp "$FOU_PORT" "$REMOTE_PUB"
        ip fou add port "$FOU_PORT" ipproto 47 2>/dev/null \
            || ip fou add port "$FOU_PORT" ipproto 47 local "$LOCAL_PUB" 2>/dev/null \
            || true
        # GRE encapsulated in UDP to peer FOU port
        if ! ip link add name GRE6 type gre \
            local "$LOCAL_PUB" remote "$REMOTE_PUB" ttl 255 key "$GRE_KEY" \
            encap fou encap-sport auto encap-dport "$FOU_PORT"; then
            echo "FOU GRE create failed" >&2
            exit 1
        fi
        ip addr add "$TUN_ADDR" dev GRE6 || true
        ip link set GRE6 mtu "$MTU"
        ip link set GRE6 up || exit 1
        ethtool -K GRE6 tso off gso off gro off >/dev/null 2>&1 || true
        setup_forward_mss GRE6
        ;;

    wg)
        if [ ! -f "$WG_CONF" ]; then
            echo "Missing $WG_CONF" >&2
            exit 1
        fi
        wg-quick up gre6tun || exit 1
        DEV="gre6tun"
        setup_forward_mss gre6tun
        ;;

    gre6)
        if [ "$MODE" = "iran" ]; then
            LOCAL_V6="$IRAN_IP"; REMOTE_V6="$KHAREJ_IP"; TUN_ADDR="172.16.1.1/30"
        else
            LOCAL_V6="$KHAREJ_IP"; REMOTE_V6="$IRAN_IP"; TUN_ADDR="172.16.1.2/30"
        fi
        ip link add name GRE6 type ip6gre local "$LOCAL_V6" remote "$REMOTE_V6" || exit 1
        ip addr add "$TUN_ADDR" dev GRE6 || true
        ip link set GRE6 mtu "$MTU"
        ip link set GRE6 up || exit 1
        setup_forward_mss GRE6
        ;;

    6to4)
        if [ "$MODE" = "iran" ]; then
            ip tunnel add SIT6 mode sit remote "$KHAREJ_IP" local "$IRAN_IP" ttl 255 || exit 1
            ip link set SIT6 mtu "$SIT_MTU"; ip link set SIT6 up
            ip -6 addr add "$SIT_IRAN_V6" dev SIT6 || exit 1
            LOCAL_V6="$SIT_IRAN_HOST"; REMOTE_V6="$SIT_KHAREJ_HOST"
            TUN_ADDR="172.16.1.1/30"
        else
            ip tunnel add SIT6 mode sit remote "$IRAN_IP" local "$KHAREJ_IP" ttl 255 || exit 1
            ip link set SIT6 mtu "$SIT_MTU"; ip link set SIT6 up
            ip -6 addr add "$SIT_KHAREJ_V6" dev SIT6 || exit 1
            LOCAL_V6="$SIT_KHAREJ_HOST"; REMOTE_V6="$SIT_IRAN_HOST"
            TUN_ADDR="172.16.1.2/30"
        fi
        sleep 1
        ip link add name GRE6 type ip6gre local "$LOCAL_V6" remote "$REMOTE_V6" || exit 1
        ip addr add "$TUN_ADDR" dev GRE6 || true
        ip link set GRE6 mtu "$MTU"
        ip link set GRE6 up || exit 1
        setup_forward_mss GRE6
        ;;

    *)
        echo "Unknown TRANSPORT=$TRANSPORT" >&2
        exit 1
        ;;
esac

if [ "$MODE" = "iran" ]; then
    setup_iran_nat
fi

exit 0
UPEOF

    cat > "$DOWN_SCRIPT" << 'DOWNEOF'
#!/usr/bin/env bash
STATE_FILE="/etc/gre6-tunnel/state.conf"
NAT_CHAIN="GRE6_TUNNEL"
WG_CONF="/etc/wireguard/gre6tun.conf"

[ -f "$STATE_FILE" ] && source "$STATE_FILE"

FOU_PORT="${FOU_PORT:-5555}"

if [ "${MODE:-}" = "iran" ]; then
    iptables -t nat -D PREROUTING -j "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null || true
fi

iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

if [ -n "${KHAREJ_IP:-}" ] && [ -n "${FOU_PORT:-}" ]; then
    iptables -D INPUT -p udp --dport "$FOU_PORT" -s "$KHAREJ_IP" -j ACCEPT 2>/dev/null || true
fi
if [ -n "${IRAN_IP:-}" ] && [ -n "${FOU_PORT:-}" ]; then
    iptables -D INPUT -p udp --dport "$FOU_PORT" -s "$IRAN_IP" -j ACCEPT 2>/dev/null || true
fi
if [ -n "${WG_PORT:-}" ]; then
    [ -n "${KHAREJ_IP:-}" ] && iptables -D INPUT -p udp --dport "$WG_PORT" -s "$KHAREJ_IP" -j ACCEPT 2>/dev/null || true
    [ -n "${IRAN_IP:-}" ] && iptables -D INPUT -p udp --dport "$WG_PORT" -s "$IRAN_IP" -j ACCEPT 2>/dev/null || true
fi

for d in GRE6 gre6tun; do
    iptables -D FORWARD -i "$d" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$d" -j ACCEPT 2>/dev/null || true
done

if command -v wg-quick >/dev/null 2>&1; then
    wg-quick down gre6tun >/dev/null 2>&1 || true
fi
rm -f "$WG_CONF" 2>/dev/null || true

if ip link show GRE6 >/dev/null 2>&1; then
    ip link set GRE6 down 2>/dev/null || true
    ip link delete GRE6 2>/dev/null || true
fi
if ip link show SIT6 >/dev/null 2>&1; then
    ip link set SIT6 down 2>/dev/null || true
    ip link delete SIT6 2>/dev/null || true
fi
ip fou del port "$FOU_PORT" 2>/dev/null || true

exit 0
DOWNEOF

    chmod +x "$UP_SCRIPT" "$DOWN_SCRIPT"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Universal GRE/FOU/WG Tunnel (Iran-Kharej)
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
}

gen_wg_keys_pair() {
    # Generate local keypair; peer public key must be exchanged — we use a shared PSK style:
    # For simple setup we generate BOTH keys on iran and print for kharej, OR generate deterministic-less
    # Better UX: generate keys on each side and show the local public key to paste on the other.
    # For one-shot simplicity: create shared config using wg genkey on each side during configure.
    true
}

write_wg_conf() {
    local mode="$1" local_ip="$2" remote_ip="$3" tun_addr="$4" priv="$5" peer_pub="$6" port="$7" mtu="$8"
    mkdir -p /etc/wireguard
    cat > "$WG_CONF" << EOF
[Interface]
PrivateKey = ${priv}
Address = ${tun_addr}
ListenPort = ${port}
MTU = ${mtu}

[Peer]
PublicKey = ${peer_pub}
Endpoint = ${remote_ip}:${port}
AllowedIPs = 172.16.1.0/30
PersistentKeepalive = 25
EOF
    chmod 600 "$WG_CONF"
}

test_tunnel() {
    local peer="$1"
    print_step "ping $peer ..."
    if ping -c 4 -W 2 "$peer" >/dev/null 2>&1; then
        print_success "Tunnel OK — ping works."
        return 0
    fi
    print_warning "Interface may be UP but ping failed."
    echo "  Check BOTH sides use same TRANSPORT and port."
    echo "  From Iran:  ping 172.16.1.2"
    echo "  From Kharej: ping 172.16.1.1"
    echo "  Logs: journalctl -u gre6-tunnel.service -xe"
    return 1
}

apply_tunnel() {
    local peer="$1"
    systemctl enable gre6-tunnel.service >/dev/null 2>&1 || true
    systemctl restart gre6-tunnel.service
    sleep 2
    if systemctl is-active --quiet gre6-tunnel.service; then
        print_success "Service active."
        ip -br link show GRE6 2>/dev/null || true
        ip -br link show gre6tun 2>/dev/null || true
        [ -n "$peer" ] && test_tunnel "$peer"
    else
        print_error "Service failed. journalctl -u gre6-tunnel.service -n 40 --no-pager"
        journalctl -u gre6-tunnel.service -n 40 --no-pager 2>/dev/null || true
    fi
}

# ---------- WireGuard interactive pair setup ----------
configure_wg_side() {
    local mode="$1" local_pub="$2" remote_pub="$3" mtu="$4" wg_port="$5"
    if ! wg_available; then
        try_install_wireguard || {
            print_error "WireGuard not available."
            return 1
        }
    fi

    mkdir -p "$STATE_DIR/wg"
    local priv pub
    if [ ! -f "$STATE_DIR/wg/private.key" ]; then
        priv=$(wg genkey)
        echo "$priv" > "$STATE_DIR/wg/private.key"
        chmod 600 "$STATE_DIR/wg/private.key"
        echo "$priv" | wg pubkey > "$STATE_DIR/wg/public.key"
    fi
    priv=$(cat "$STATE_DIR/wg/private.key")
    pub=$(cat "$STATE_DIR/wg/public.key")

    echo ""
    print_success "Public key این سرور:"
    echo "$pub"
    echo ""
    local peer_pub
    read -rp "Public key سرور مقابل را وارد کنید: " peer_pub
    if [ -z "$peer_pub" ]; then
        print_error "Peer public key required."
        return 1
    fi

    local tun_addr
    if [ "$mode" = "iran" ]; then
        tun_addr="172.16.1.1/30"
    else
        tun_addr="172.16.1.2/30"
    fi

    write_wg_conf "$mode" "$local_pub" "$remote_pub" "$tun_addr" "$priv" "$peer_pub" "$wg_port" "$mtu"
    open_firewall_udp "$wg_port" "$remote_pub"
}

configure_iran() {
    ensure_deps || { pause; return; }

    local det4 det6
    det4=$(get_public_ipv4 || true)
    det6=$(get_public_ipv6 || true)
    echo "IPv4: ${det4:-Not Detected}"
    echo "IPv6: ${det6:-Not Detected}"

    local transport
    transport=$(pick_transport) || { pause; return; }
    print_step "TRANSPORT=$transport"

    local iran_ip kharej_ip ports clean_ports mtu fou_port wg_port
    fou_port="$DEFAULT_FOU_PORT"
    wg_port="$DEFAULT_WG_PORT"

    case "$transport" in
        fou|wg|6to4)
            read -rp "Iran public IPv4 [${det4}]: " iran_ip
            iran_ip="${iran_ip:-$det4}"
            validate_ipv4 "$iran_ip" || { print_error "Bad IPv4"; pause; return; }
            read -rp "Kharej public IPv4: " kharej_ip
            validate_ipv4 "$kharej_ip" || { print_error "Bad IPv4"; pause; return; }
            ;;
        gre6)
            read -rp "Iran public IPv6 [${det6}]: " iran_ip
            iran_ip="${iran_ip:-$det6}"
            validate_ipv6 "$iran_ip" || { print_error "Bad IPv6"; pause; return; }
            read -rp "Kharej public IPv6: " kharej_ip
            validate_ipv6 "$kharej_ip" || { print_error "Bad IPv6"; pause; return; }
            ;;
    esac

    if [ "$transport" = "fou" ]; then
        fou_available || { print_error "FOU not supported on this kernel. Choose WG/Auto."; pause; return; }
        read -rp "FOU UDP port [${DEFAULT_FOU_PORT}]: " fou_port
        fou_port="${fou_port:-$DEFAULT_FOU_PORT}"
        validate_port "$fou_port" || { print_error "Bad port"; pause; return; }
        mtu=$(ask_mtu "$DEFAULT_MTU_FOU")
        open_firewall_udp "$fou_port" "$kharej_ip"
    elif [ "$transport" = "wg" ]; then
        read -rp "WireGuard UDP port [${DEFAULT_WG_PORT}]: " wg_port
        wg_port="${wg_port:-$DEFAULT_WG_PORT}"
        validate_port "$wg_port" || { print_error "Bad port"; pause; return; }
        mtu=$(ask_mtu "$DEFAULT_MTU_WG")
        configure_wg_side iran "$iran_ip" "$kharej_ip" "$mtu" "$wg_port" || { pause; return; }
    elif [ "$transport" = "gre6" ]; then
        mtu=$(ask_mtu "$DEFAULT_MTU_GRE6")
    else
        mtu=$(ask_mtu 1280)
    fi

    read -rp "Inbound ports (e.g. 443,2080): " ports
    if ! clean_ports=$(validate_port_list "$ports"); then
        pause; return
    fi

    mkdir -p "$STATE_DIR"
    cat > "$STATE_FILE" << EOF
MODE=iran
TRANSPORT=${transport}
IRAN_IP=${iran_ip}
KHAREJ_IP=${kharej_ip}
PORTS=${clean_ports}
MTU=${mtu}
FOU_PORT=${fou_port}
WG_PORT=${wg_port}
GRE_KEY=1001
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

    local det4 det6
    det4=$(get_public_ipv4 || true)
    det6=$(get_public_ipv6 || true)
    echo "IPv4: ${det4:-Not Detected}"
    echo "IPv6: ${det6:-Not Detected}"

    local transport
    transport=$(pick_transport) || { pause; return; }
    print_step "TRANSPORT=$transport"
    print_warning "باید با ایران یکی باشد."

    local iran_ip kharej_ip mtu fou_port wg_port
    fou_port="$DEFAULT_FOU_PORT"
    wg_port="$DEFAULT_WG_PORT"

    case "$transport" in
        fou|wg|6to4)
            read -rp "Kharej public IPv4 [${det4}]: " kharej_ip
            kharej_ip="${kharej_ip:-$det4}"
            validate_ipv4 "$kharej_ip" || { print_error "Bad IPv4"; pause; return; }
            read -rp "Iran public IPv4: " iran_ip
            validate_ipv4 "$iran_ip" || { print_error "Bad IPv4"; pause; return; }
            ;;
        gre6)
            read -rp "Kharej public IPv6 [${det6}]: " kharej_ip
            kharej_ip="${kharej_ip:-$det6}"
            validate_ipv6 "$kharej_ip" || { print_error "Bad IPv6"; pause; return; }
            read -rp "Iran public IPv6: " iran_ip
            validate_ipv6 "$iran_ip" || { print_error "Bad IPv6"; pause; return; }
            ;;
    esac

    if [ "$transport" = "fou" ]; then
        fou_available || { print_error "FOU not supported. Choose WG/Auto."; pause; return; }
        read -rp "FOU UDP port [${DEFAULT_FOU_PORT}]: " fou_port
        fou_port="${fou_port:-$DEFAULT_FOU_PORT}"
        validate_port "$fou_port" || { print_error "Bad port"; pause; return; }
        mtu=$(ask_mtu "$DEFAULT_MTU_FOU")
        open_firewall_udp "$fou_port" "$iran_ip"
    elif [ "$transport" = "wg" ]; then
        read -rp "WireGuard UDP port [${DEFAULT_WG_PORT}]: " wg_port
        wg_port="${wg_port:-$DEFAULT_WG_PORT}"
        validate_port "$wg_port" || { print_error "Bad port"; pause; return; }
        mtu=$(ask_mtu "$DEFAULT_MTU_WG")
        configure_wg_side kharej "$kharej_ip" "$iran_ip" "$mtu" "$wg_port" || { pause; return; }
    elif [ "$transport" = "gre6" ]; then
        mtu=$(ask_mtu "$DEFAULT_MTU_GRE6")
    else
        mtu=$(ask_mtu 1280)
    fi

    mkdir -p "$STATE_DIR"
    cat > "$STATE_FILE" << EOF
MODE=kharej
TRANSPORT=${transport}
IRAN_IP=${iran_ip}
KHAREJ_IP=${kharej_ip}
PORTS=
MTU=${mtu}
FOU_PORT=${fou_port}
WG_PORT=${wg_port}
GRE_KEY=1001
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
        print_warning "Nothing configured."
        pause; return
    fi
    print_step "Removing..."
    systemctl stop gre6-tunnel.service >/dev/null 2>&1 || true
    systemctl disable gre6-tunnel.service >/dev/null 2>&1 || true
    [ -x "$DOWN_SCRIPT" ] && "$DOWN_SCRIPT" || true
    rm -f "$SERVICE_FILE"
    rm -rf "$STATE_DIR"
    rm -f "$WG_CONF"
    systemctl daemon-reload
    print_success "Removed."
    pause
}

status_tunnel() {
    echo "=== service ==="
    systemctl --no-pager --full status gre6-tunnel.service 2>/dev/null | head -n 20 || true
    echo ""
    echo "=== state ==="
    [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "(none)"
    echo ""
    echo "=== links ==="
    ip -br link show GRE6 2>/dev/null || echo "GRE6: missing"
    ip -br link show gre6tun 2>/dev/null || true
    ip -br link show SIT6 2>/dev/null || true
    echo ""
    echo "=== addrs ==="
    ip addr show GRE6 2>/dev/null || true
    ip addr show gre6tun 2>/dev/null || true
    echo ""
    echo "=== fou ==="
    ip fou show 2>/dev/null || true
    echo ""
    if [ -f "$STATE_FILE" ]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
        if [ "${MODE:-}" = "iran" ]; then
            ping -c 3 -W 2 172.16.1.2 || true
        else
            ping -c 3 -W 2 172.16.1.1 || true
        fi
    fi
    pause
}

main_menu() {
    while true; do
        clear
        local v4 v6
        v4=$(get_public_ipv4 || true)
        v6=$(get_public_ipv6 || true)
        echo "IPv4: ${v4:-Not Detected} | IPv6: ${v6:-Not Detected}"
        echo "=============================================="
        echo "  Universal Tunnel (FOU / WG / GRE6)"
        echo "=============================================="
        echo "1) Configure Iran Server"
        echo "2) Configure Kharej Server"
        echo "3) Remove Tunnel"
        echo "4) Status / Diagnose"
        echo "0) Exit"
        echo "=============================================="
        echo "پیشنهاد: گزینه Auto یا FOU روی هر دو سرور"
        echo "=============================================="
        read -rp "Select: " opt
        case "$opt" in
            1) configure_iran ;;
            2) configure_kharej ;;
            3) remove_tunnel ;;
            4) status_tunnel ;;
            0) exit 0 ;;
            *) print_warning "Invalid."; pause ;;
        esac
    done
}

require_root
main_menu
