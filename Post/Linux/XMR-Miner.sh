#!/bin/bash
# ======================================================================
#  XMRig One‑Shot Installer for Old CentOS (no systemd)
#  Usage:   sudo ./install_xmrig.sh YOUR_WALLET [POOL_URL] [OPTIONS]
#  Default pool: pool.supportxmr.com:443   (SSL – bypasses firewalls)
#
#  Options:
#    --fix-dns   : Set public DNS (8.8.8.8) and lock /etc/resolv.conf
#    --ip IP     : Use a direct IP instead of the domain (e.g., --ip 141.94.96.71)
#
#  Offline fallback: put xmrig-6.26.0-linux-static-x64.tar.gz in
#  the same folder as this script.
# ======================================================================
set -o pipefail

# ---------- Colors ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${YELLOW}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✔]${NC} $1"; }
err()   { echo -e "${RED}[✘]${NC} $1"; exit 1; }

# ---------- Config ----------
XMRIG_VERSION="6.26.0"
INSTALL_DIR="/opt/xmrig"
LOG_FILE="/var/log/xmrig.log"
LOCK_FILE="/tmp/xmrig_stop.lock"
DEFAULT_POOL="pool.supportxmr.com:443"
BINARY="$INSTALL_DIR/xmrig"
WRAPPER="$INSTALL_DIR/run_xmrig.sh"
FIX_DNS=false
DIRECT_IP=""

# ---------- Parse arguments ----------
WALLET=""
POOL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix-dns) FIX_DNS=true; shift ;;
        --ip) DIRECT_IP="$2"; shift 2 ;;
        *)
            if [ -z "$WALLET" ]; then
                WALLET="$1"
            elif [ -z "$POOL" ]; then
                POOL="$1"
            fi
            shift
            ;;
    esac
done

[ -z "$WALLET" ] && { echo "Usage: $0 WALLET [POOL] [--fix-dns] [--ip IP]"; exit 1; }
POOL="${POOL:-$DEFAULT_POOL}"

# If direct IP provided, override pool
if [ -n "$DIRECT_IP" ]; then
    # If IP doesn't have port, append :443
    if [[ "$DIRECT_IP" != *":"* ]]; then
        DIRECT_IP="${DIRECT_IP}:443"
    fi
    POOL="$DIRECT_IP"
    info "Using direct IP pool: $POOL"
fi

# Determine if TLS should be used (port 443 → yes)
TLS_FLAG=""
if [[ "$POOL" == *":443" ]]; then
    TLS_FLAG="--tls"
fi

# Root only
[ "$(id -u)" -ne 0 ] && err "Run as root."

# ---------- 0. (Optional) Fix DNS ----------
if $FIX_DNS; then
    info "Setting public DNS servers and locking /etc/resolv.conf..."
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf
    ok "DNS locked to 8.8.8.8 / 8.8.4.4"
fi

# ---------- 0.5 DNS hijack detection (if pool is a domain) ----------
if [[ "$POOL" != *":"* ]]; then
    # no port? add default
    POOL="${POOL}:443"
fi
POOL_DOMAIN="${POOL%:*}"   # extract domain part (strip port)
if [[ "$POOL_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # It's already an IP – skip DNS checks
    info "Pool is an IP address, DNS check skipped."
else
    info "Checking DNS resolution for $POOL_DOMAIN..."
    RESOLVED_IP=""
    if command -v getent &>/dev/null; then
        RESOLVED_IP=$(getent ahosts "$POOL_DOMAIN" 2>/dev/null | awk '{print $1; exit}')
    elif command -v host &>/dev/null; then
        RESOLVED_IP=$(host "$POOL_DOMAIN" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    fi
    if [ -z "$RESOLVED_IP" ]; then
        err "Cannot resolve $POOL_DOMAIN – DNS is broken. Use --fix-dns or pass a direct IP with --ip."
    elif [[ "$RESOLVED_IP" =~ ^10\. ]] || [[ "$RESOLVED_IP" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ "$RESOLVED_IP" =~ ^192\.168\. ]] || [[ "$RESOLVED_IP" =~ ^127\. ]]; then
        warn_msg="${RED}[!]${NC} $POOL_DOMAIN resolved to a private IP ($RESOLVED_IP)."
        echo -e "$warn_msg"
        echo "Your DNS is hijacked or blocking the real pool."
        echo "   → Use --fix-dns to force Google DNS, or"
        echo "   → Rerun with:   --ip 141.94.96.71"
        echo "   (or any known SupportXMR IP)"
        echo "Continuing anyway, but mining will likely fail unless you fix DNS."
        # We'll continue, the wrapper will try to connect – it will probably fail with a private IP.
    else
        ok "DNS resolution OK ($RESOLVED_IP)"
    fi
fi

# ---------- 1. Firewall: allow outbound to pool port ----------
POOL_PORT=$(echo "$POOL" | awk -F: '{print $NF}')
if command -v iptables &>/dev/null; then
    info "Adding iptables outbound rule for port $POOL_PORT..."
    if iptables -C OUTPUT -p tcp --dport "$POOL_PORT" -j ACCEPT 2>/dev/null; then
        ok "Rule already exists."
    else
        iptables -I OUTPUT -p tcp --dport "$POOL_PORT" -j ACCEPT || err "Failed to add iptables rule"
        # Save permanently (old CentOS)
        if [ -f /etc/sysconfig/iptables ]; then
            iptables-save > /etc/sysconfig/iptables
        elif command -v service &>/dev/null && service iptables save &>/dev/null; then
            : # saved
        else
            info "iptables rule added but may not survive reboot – add it to your firewall script manually."
        fi
        ok "iptables rule added and saved."
    fi
else
    info "iptables not found – skipping firewall rule."
fi

# ---------- 2. Stop any previous miner ----------
info "Stopping any existing XMRig instances..."
pkill -f "$BINARY" 2>/dev/null || true
pkill -f "$WRAPPER" 2>/dev/null || true
rm -f "$LOCK_FILE"
sleep 2

# ---------- 3. Install XMRig if missing ----------
if [ ! -f "$BINARY" ]; then
    info "XMRig binary not found. Installing..."
    ARCHIVE="xmrig-${XMRIG_VERSION}-linux-static-x64.tar.gz"
    EXTRACT_DIR="xmrig-${XMRIG_VERSION}"
    URL="https://github.com/xmrig/xmrig/releases/download/v${XMRIG_VERSION}/${ARCHIVE}"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    mkdir -p "$INSTALL_DIR" || err "Cannot create $INSTALL_DIR"
    cd /tmp || err "Cannot access /tmp"

    # Try local file first
    if [ -f "$SCRIPT_DIR/$ARCHIVE" ]; then
        ok "Found local archive: $SCRIPT_DIR/$ARCHIVE"
        cp "$SCRIPT_DIR/$ARCHIVE" ./ || err "Failed to copy local archive"
    else
        info "Downloading XMRig v${XMRIG_VERSION}..."
        DOWNLOAD_OK=false
        if command -v wget &>/dev/null; then
            wget -q --no-check-certificate "$URL" -O "$ARCHIVE" && DOWNLOAD_OK=true
        elif command -v curl &>/dev/null; then
            curl -sSL -o "$ARCHIVE" "$URL" && DOWNLOAD_OK=true
        else
            err "Neither wget nor curl found. Install one or place $ARCHIVE in $SCRIPT_DIR"
        fi

        if ! $DOWNLOAD_OK; then
            echo ""
            err "Download failed. Place the archive in:
            $SCRIPT_DIR/$ARCHIVE
            Then run this script again."
        fi
    fi

    tar -xzf "$ARCHIVE" || err "Extraction failed (corrupt archive?)"
    cp "$EXTRACT_DIR/xmrig" "$BINARY" || err "Copy failed"
    chmod +x "$BINARY"
    rm -rf "$ARCHIVE" "$EXTRACT_DIR"
    ok "XMRig installed to $BINARY"
else
    ok "XMRig already present"
fi

# ---------- 4. Create restart wrapper (unbuffered logging) ----------
info "Creating wrapper script..."
cat > "$WRAPPER" << WRAPPER_EOF
#!/bin/bash
BINARY="$BINARY"
POOL="$POOL"
WALLET="$WALLET"
LOG_FILE="$LOG_FILE"
LOCK_FILE="$LOCK_FILE"
TLS_FLAG="$TLS_FLAG"

echo "\$(date): Wrapper started." >> "\$LOG_FILE"
while [ ! -f "\$LOCK_FILE" ]; do
    echo "\$(date): Starting XMRig..." >> "\$LOG_FILE"
    # Force unbuffered output to log file using stdbuf and tee
    stdbuf -oL \$BINARY -o "\$POOL" -u "\$WALLET" -p x \$TLS_FLAG --randomx-no-rdmsr --donate-level=1 2>&1 | tee -a "\$LOG_FILE"
    EXIT_CODE=\$?
    echo "\$(date): XMRig exited with code \$EXIT_CODE. Restarting in 10s..." >> "\$LOG_FILE"
    sleep 10
done
echo "\$(date): Stop lock detected. Exiting." >> "\$LOG_FILE"
rm -f "\$LOCK_FILE"
WRAPPER_EOF

chmod +x "$WRAPPER"
ok "Wrapper created at $WRAPPER"

# ---------- 5. Boot persistence (rc.local) ----------
info "Enabling boot start via /etc/rc.local..."
if [ ! -f /etc/rc.local ]; then
    echo "#!/bin/bash" > /etc/rc.local
    chmod +x /etc/rc.local
fi
chmod +x /etc/rc.local 2>/dev/null || true

# Remove any old entries
sed -i '/run_xmrig.sh/d' /etc/rc.local
if grep -q "^exit 0" /etc/rc.local; then
    sed -i "/^exit 0$/i nohup $WRAPPER >> $LOG_FILE 2>&1 &" /etc/rc.local
else
    echo "nohup $WRAPPER >> $LOG_FILE 2>&1 &" >> /etc/rc.local
fi
ok "Boot persistence set."

# ---------- 6. Start the miner now ----------
info "Starting XMRig service..."
rm -f "$LOCK_FILE"
nohup "$WRAPPER" >> "$LOG_FILE" 2>&1 &
sleep 4

if ps aux | grep -v grep | grep -q "$BINARY"; then
    ok "XMRig is running! PID: $(pgrep -f "$BINARY")"
else
    err "XMRig failed to start. Check log: tail -30 $LOG_FILE"
fi

# ---------- Final info ----------
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   XMRig setup SUCCESSFUL${NC}"
echo -e "${GREEN}========================================${NC}"
echo " Wallet   : $WALLET"
echo " Pool     : $POOL"
echo " TLS      : ${TLS_FLAG:-off}"
echo " Logs     : tail -f $LOG_FILE"
echo " Stop     : touch $LOCK_FILE && pkill -f xmrig"
echo " Status   : ps aux | grep xmrig"
echo ""
echo "Wait ~1 min, then watch live output:"
echo "  tail -f $LOG_FILE"
