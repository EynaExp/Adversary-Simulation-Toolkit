#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# netinfo.sh – Compact Linux network, domain & public IP information (v4)
# Usage:  ./netinfo.sh [ -o FILE ] [ -j ] [ -h ]
#   -o FILE   Write output to FILE instead of stdout
#   -j        Output JSON format (otherwise plain text)
#   -h        Show this help message
# ------------------------------------------------------------------------------

OUTPUT="/dev/stdout"
FORMAT="text"
HELP=0

usage() {
    grep '^# Usage:' "$0" | cut -c3-
    exit "${1:-0}"
}

while getopts "o:jh" opt; do
    case "$opt" in
        o) OUTPUT="$OPTARG" ;;
        j) FORMAT="json" ;;
        h) HELP=1 ;;
        *) usage 1 ;;
    esac
done
shift $((OPTIND-1))
[[ $HELP -eq 1 ]] && usage 0

# -----------------------------------------------------------
# Helpers
# -----------------------------------------------------------
check_cmd() {
    local cmd="$1"
    for p in "" /sbin /usr/sbin /usr/local/sbin; do
        if command -v "${p}/${cmd}" >/dev/null 2>&1; then
            echo "${p}/${cmd}"
            return 0
        fi
    done
    return 1
}

escape_json() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\n/\\n/g'
}

# Quick HTTP fetch with timeout, prefer curl > wget
http_get() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -s --max-time 3 "$url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- -T 3 "$url" 2>/dev/null
    fi
}

# Reverse DNS lookup – try dig, then host, then nslookup
rev_dns() {
    local ip="$1"
    if command -v dig >/dev/null 2>&1; then
        dig +short -x "$ip" 2>/dev/null | head -1
    elif command -v host >/dev/null 2>&1; then
        host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//' | head -1
    elif command -v nslookup >/dev/null 2>&1; then
        nslookup "$ip" 2>/dev/null | awk '/name =/ {print $4}' | sed 's/\.$//' | head -1
    fi
}

# -----------------------------------------------------------
# Discover tools
# -----------------------------------------------------------
IP=$(check_cmd ip || true)
IFCONFIG=$(check_cmd ifconfig || true)
ROUTE=$(check_cmd route || true)
RESOLVCTL=$(check_cmd resolvectl || true)

USE_IP=false
if [[ -n "$IP" && "$(basename "$IP")" == "ip" ]]; then
    USE_IP=true
fi

# -----------------------------------------------------------
# Gather local info (unchanged)
# -----------------------------------------------------------
HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
FQDN=$(hostname -f 2>/dev/null || hostname --fqdn 2>/dev/null || echo "$HOSTNAME")
DNSDOMAIN=$(hostname -d 2>/dev/null || dnsdomainname 2>/dev/null || echo "")

DNS_SERVERS=""
SEARCH_DOMAINS=""
if [[ -n "$RESOLVCTL" ]]; then
    DNS_SERVERS=$($RESOLVCTL dns 2>/dev/null | grep -v '^Link\|^$' | awk '{print $2}' | sort -u | paste -sd ',' - || true)
    SEARCH_DOMAINS=$($RESOLVCTL domain 2>/dev/null | grep -v '^Link\|^$' | awk '{print $2}' | sort -u | paste -sd ',' - || true)
fi
if [[ -z "$DNS_SERVERS" && -r /etc/resolv.conf ]]; then
    DNS_SERVERS=$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | paste -sd ',' -)
    SEARCH_DOMAINS=$(grep -E '^search' /etc/resolv.conf 2>/dev/null | sed 's/^search //;s/  */,/g' | paste -sd ',' -)
fi

declare -A IFACE_MAP=()
if $USE_IP; then
    for iface in $(ls /sys/class/net 2>/dev/null); do
        [[ "$iface" == "lo" ]] && continue
        mac=$(cat "/sys/class/net/${iface}/address" 2>/dev/null || echo "unknown")
        state=$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "unknown")
        mtu=$(cat "/sys/class/net/${iface}/mtu" 2>/dev/null || echo "")
        ipv4=$($IP -4 -o addr show "$iface" 2>/dev/null | awk '{print $4}' | paste -sd ',' - || true)
        ipv6=$($IP -6 -o addr show "$iface" 2>/dev/null | awk '{print $4}' | paste -sd ',' - || true)
        IFACE_MAP["${iface}_mac"]="$mac"
        IFACE_MAP["${iface}_state"]="$state"
        IFACE_MAP["${iface}_mtu"]="$mtu"
        IFACE_MAP["${iface}_ipv4"]="$ipv4"
        IFACE_MAP["${iface}_ipv6"]="$ipv6"
    done
elif [[ -n "$IFCONFIG" ]]; then
    cur_iface=""
    while IFS= read -r line; do
        if [[ -z "$line" || ! "$line" =~ ^[[:space:]] ]]; then
            if [[ -n "$cur_iface" && "$cur_iface" != "lo" ]]; then
                IFACE_MAP["${cur_iface}_mac"]="$cur_mac"
                IFACE_MAP["${cur_iface}_state"]="unknown"
                IFACE_MAP["${cur_iface}_mtu"]="$cur_mtu"
                IFACE_MAP["${cur_iface}_ipv4"]="$cur_ipv4"
                IFACE_MAP["${cur_iface}_ipv6"]="$cur_ipv6"
            fi
            cur_iface=$(echo "$line" | awk '{print $1; exit}')
            cur_mac=""; cur_mtu=""; cur_ipv4=""; cur_ipv6=""
            cur_mac=$(echo "$line" | grep -oE '([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}' || echo "unknown")
            cur_mtu=$(echo "$line" | grep -oE 'MTU:[0-9]+' | cut -d: -f2 || echo "")
        else
            if [[ "$line" =~ "inet addr:" ]]; then
                addr=$(echo "$line" | sed 's/.*inet addr:\([^ ]*\).*/\1/')
                cur_ipv4="${cur_ipv4:+$cur_ipv4,}$addr"
            elif [[ "$line" =~ "inet6 addr:" ]]; then
                addr=$(echo "$line" | sed 's/.*inet6 addr: *\([^ ]*\).*/\1/')
                cur_ipv6="${cur_ipv6:+$cur_ipv6,}$addr"
            fi
        fi
    done < <($IFCONFIG -a 2>/dev/null)
    if [[ -n "$cur_iface" && "$cur_iface" != "lo" ]]; then
        IFACE_MAP["${cur_iface}_mac"]="$cur_mac"
        IFACE_MAP["${cur_iface}_state"]="unknown"
        IFACE_MAP["${cur_iface}_mtu"]="$cur_mtu"
        IFACE_MAP["${cur_iface}_ipv4"]="$cur_ipv4"
        IFACE_MAP["${cur_iface}_ipv6"]="$cur_ipv6"
    fi
fi

GW4=""
GW6=""
if $USE_IP; then
    GW4=$($IP -4 route show default 2>/dev/null | awk '{print $3; exit}' || true)
    GW6=$($IP -6 route show default 2>/dev/null | awk '{print $3; exit}' || true)
elif [[ -n "$ROUTE" ]]; then
    GW4=$($ROUTE -n 2>/dev/null | awk '/^0.0.0.0/ {print $2; exit}' || true)
fi

# -----------------------------------------------------------
# NEW: Public IP & Reverse DNS
# -----------------------------------------------------------
PUB_IP4=""
PUB_IP6=""
PTR4=""
PTR6=""

# Try multiple public IP services (IPv4)
for url in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
    ip=$(http_get "$url")
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        PUB_IP4="$ip"
        break
    fi
done

# Try IPv6 (if the machine has IPv6 connectivity)
if command -v dig >/dev/null 2>&1; then
    # Use OpenDNS to discover IPv6 (myip.opendns.com AAAA returns IPv6)
    ip6=$(dig +short AAAA myip.opendns.com @resolver1.opendns.com 2>/dev/null | head -1)
    [[ -n "$ip6" ]] && PUB_IP6="$ip6"
fi

# If no IPv6 from dig, try HTTP services
if [[ -z "$PUB_IP6" ]]; then
    for url in "https://api6.ipify.org" "https://v6.ifconfig.co" "https://ipv6.icanhazip.com"; do
        ip6=$(http_get "$url")
        if [[ -n "$ip6" && "$ip6" =~ : ]]; then
            PUB_IP6="$ip6"
            break
        fi
    done
fi

# Reverse DNS for each public IP
[[ -n "$PUB_IP4" ]] && PTR4=$(rev_dns "$PUB_IP4")
[[ -n "$PUB_IP6" ]] && PTR6=$(rev_dns "$PUB_IP6")

# -----------------------------------------------------------
# Output
# -----------------------------------------------------------
if [[ "$FORMAT" == "json" ]]; then
    {
        printf '{\n'
        printf '  "hostname": "%s",\n' "$(escape_json "$HOSTNAME")"
        printf '  "fqdn": "%s",\n' "$(escape_json "$FQDN")"
        printf '  "dns_domain": "%s",\n' "$(escape_json "$DNSDOMAIN")"
        printf '  "dns_servers": "%s",\n' "$(escape_json "$DNS_SERVERS")"
        printf '  "search_domains": "%s",\n' "$(escape_json "$SEARCH_DOMAINS")"

        echo '  "interfaces": ['
        first=true
        for iface in $(ls /sys/class/net 2>/dev/null; echo ""); do
            [[ -z "$iface" || "$iface" == "lo" ]] && continue
            $first || printf ',\n'
            first=false
            mac="${IFACE_MAP[${iface}_mac]:-unknown}"
            state="${IFACE_MAP[${iface}_state]:-unknown}"
            mtu="${IFACE_MAP[${iface}_mtu]:-}"
            ipv4="${IFACE_MAP[${iface}_ipv4]:-}"
            ipv6="${IFACE_MAP[${iface}_ipv6]:-}"
            printf '    {\n'
            printf '      "name": "%s",\n' "$(escape_json "$iface")"
            printf '      "mac": "%s",\n' "$(escape_json "$mac")"
            printf '      "state": "%s",\n' "$(escape_json "$state")"
            printf '      "mtu": "%s",\n' "$(escape_json "$mtu")"
            printf '      "ipv4_addresses": "%s",\n' "$(escape_json "$ipv4")"
            printf '      "ipv6_addresses": "%s"' "$(escape_json "$ipv6")"
            printf '\n    }'
        done
        printf '\n  ],\n'
        printf '  "default_gateway4": "%s",\n' "$(escape_json "${GW4:-}")"
        printf '  "default_gateway6": "%s",\n' "$(escape_json "${GW6:-}")"

        # Public IP section
        printf '  "public_ipv4": "%s",\n' "$(escape_json "${PUB_IP4:-}")"
        printf '  "public_ipv6": "%s",\n' "$(escape_json "${PUB_IP6:-}")"
        printf '  "reverse_dns_v4": "%s",\n' "$(escape_json "${PTR4:-}")"
        printf '  "reverse_dns_v6": "%s"\n' "$(escape_json "${PTR6:-}")"
        printf '}\n'
    } > "$OUTPUT"
else
    {
        echo "=== HOST & DOMAIN ==="
        echo "Hostname       : $HOSTNAME"
        echo "FQDN           : $FQDN"
        echo "DNS Domain     : ${DNSDOMAIN:-<none>}"
        echo ""
        echo "=== DNS CONFIGURATION ==="
        echo "DNS Servers    : ${DNS_SERVERS:-<none>}"
        echo "Search Domains : ${SEARCH_DOMAINS:-<none>}"
        echo ""
        echo "=== NETWORK INTERFACES ==="
        for iface in $(ls /sys/class/net 2>/dev/null); do
            [[ "$iface" == "lo" ]] && continue
            echo "  [$iface]"
            echo "    MAC             : ${IFACE_MAP[${iface}_mac]:-unknown}"
            echo "    State           : ${IFACE_MAP[${iface}_state]:-unknown}"
            echo "    MTU             : ${IFACE_MAP[${iface}_mtu]:-}"
            echo "    IPv4 Addresses  : ${IFACE_MAP[${iface}_ipv4]:-<none>}"
            echo "    IPv6 Addresses  : ${IFACE_MAP[${iface}_ipv6]:-<none>}"
            echo ""
        done
        echo "=== ROUTING (DEFAULT GATEWAYS) ==="
        echo "IPv4 Default GW : ${GW4:-<none>}"
        echo "IPv6 Default GW : ${GW6:-<none>}"
        echo ""
        echo "=== PUBLIC IP & REVERSE DNS ==="
        echo "Public IPv4     : ${PUB_IP4:-<could not detect>}"
        echo "Reverse DNS v4  : ${PTR4:-<none>}"
        echo "Public IPv6     : ${PUB_IP6:-<could not detect>}"
        echo "Reverse DNS v6  : ${PTR6:-<none>}"
    } > "$OUTPUT"
fi

if [[ "$OUTPUT" != "/dev/stdout" && "$OUTPUT" != "-" ]]; then
    echo "Report saved to $OUTPUT"
fi
