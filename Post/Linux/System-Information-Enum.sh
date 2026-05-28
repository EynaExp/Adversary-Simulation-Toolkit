#!/usr/bin/env bash
# =============================================================================
# sysinfo – portable Linux system information collector
# Usage: ./sysinfo.sh [-j]
#   -j          Output in JSON format (requires jq)
#   (no flag)   Clean, minimal human-readable output
# =============================================================================

set -euo pipefail

# Helper: safely execute a command and return its output (or "N/A" on failure)
safe_cmd() {
    local output
    output="$(eval "$@" 2>/dev/null)" && echo "$output" || echo "N/A"
}

# -----------------------------------------------------------------------------
# 1. OS information
# -----------------------------------------------------------------------------
get_os_info() {
    local os_name="N/A"
    local kernel="N/A"
    local arch="N/A"

    if [ -f /etc/os-release ]; then
        os_name=$( ( . /etc/os-release && echo "${PRETTY_NAME:-${NAME}}") )
    fi

    kernel=$(uname -r)
    arch=$(uname -m)

    echo "${os_name} (Linux ${kernel} ${arch})"
}

# -----------------------------------------------------------------------------
# 2. CPU information
# -----------------------------------------------------------------------------
get_cpu_info() {
    local model="N/A"
    local cores="N/A"

    if command -v lscpu &>/dev/null; then
        model=$(lscpu | awk -F: '/Model name/ { gsub(/^[ \t]+/,""); print $2 }')
        cores=$(lscpu | awk -F: '/^CPU\(s\)/ { gsub(/^[ \t]+/,""); print $2 }')
    else
        model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')
        cores=$(grep -c '^processor' /proc/cpuinfo)
    fi

    echo "${model:-N/A} (${cores:-N/A} cores)"
}

# -----------------------------------------------------------------------------
# 3. RAM information (values in bytes)
# -----------------------------------------------------------------------------
get_ram_info() {
    local total=0 free=0 used=0 unit="B"
    local total_kb free_kb

    if [ -f /proc/meminfo ]; then
        total_kb=$(awk '/^MemTotal/ {print $2}' /proc/meminfo)
        free_kb=$(awk '/^MemAvailable/ {print $2}' /proc/meminfo)
        if [ -z "$free_kb" ]; then
            free_kb=$(awk '/^MemFree/ {print $2}' /proc/meminfo)
        fi
        total=$((total_kb * 1024))
        free=$((free_kb * 1024))
        used=$((total - free))
    fi

    echo "${total} ${used} ${free} ${unit}"
}

# -----------------------------------------------------------------------------
# 4. Disk & drive information
# -----------------------------------------------------------------------------
get_disk_info() {
    local out=""
    if command -v lsblk &>/dev/null; then
        out+="DISKS:\n"
        while IFS= read -r line; do
            local name size model
            name=$(echo "$line" | awk '{print $1}')
            size=$(echo "$line" | awk '{print $2}')
            model=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ *$//')
            out+="  /dev/${name}: ${size} (model: ${model})\n"
        done < <(lsblk -dno NAME,SIZE,MODEL 2>/dev/null || true)
    fi

    if command -v df &>/dev/null; then
        out+="MOUNTS:\n"
        while IFS= read -r line; do
            [[ "$line" =~ ^Filesystem ]] && continue
            local fs total used avail mnt
            fs=$(echo "$line" | awk '{print $1}')
            total=$(echo "$line" | awk '{print $2}')
            used=$(echo "$line" | awk '{print $3}')
            avail=$(echo "$line" | awk '{print $4}')
            mnt=$(echo "$line" | awk '{print $5}')
            out+="  ${fs} on ${mnt} (total: ${total}K, used: ${used}K, avail: ${avail}K)\n"
        done < <(df -P -T 2>/dev/null | grep -v -E '^(tmpfs|devtmpfs|overlay|squashfs)')
    else
        out+="MOUNTS: N/A\n"
    fi

    echo -e "$out"
}

# -----------------------------------------------------------------------------
# 5. Users information (usernames and their groups)
# -----------------------------------------------------------------------------
get_users_info() {
    local out="USERS:\n"
    while IFS=: read -r user pass uid gid gecos home shell; do
        if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] || [ "$user" = "root" ]; then
            local groups
            groups=$(id -Gn "$user" 2>/dev/null | tr ' ' ',')
            out+="  ${user} (groups: ${groups})\n"
        fi
    done < /etc/passwd
    echo -e "$out"
}

# -----------------------------------------------------------------------------
# Human-readable output
# -----------------------------------------------------------------------------
output_clean() {
    local os_info cpu_info ram_raw disk_info users_info
    os_info=$(get_os_info)
    cpu_info=$(get_cpu_info)
    ram_raw=$(get_ram_info)
    disk_info=$(get_disk_info)
    users_info=$(get_users_info)

    read -r total_bytes used_bytes free_bytes unit <<< "$ram_raw"
    local total_hr used_hr free_hr
    total_hr=$(numfmt --to=iec --suffix=B "$total_bytes" 2>/dev/null || echo "${total_bytes} B")
    used_hr=$(numfmt --to=iec --suffix=B "$used_bytes" 2>/dev/null || echo "${used_bytes} B")
    free_hr=$(numfmt --to=iec --suffix=B "$free_bytes" 2>/dev/null || echo "${free_bytes} B")

    cat <<EOF
--- System Information ---
OS    : $os_info
CPU   : $cpu_info
RAM   : Total: ${total_hr}, Used: ${used_hr}, Free: ${free_hr}
$disk_info
$users_info
EOF
}

# -----------------------------------------------------------------------------
# JSON output
# -----------------------------------------------------------------------------
output_json() {
    local os_info cpu_info ram_raw
    os_info=$(get_os_info)
    cpu_info=$(get_cpu_info)
    ram_raw=$(get_ram_info)
    read -r total_bytes used_bytes free_bytes unit <<< "$ram_raw"

    local os_name kernel arch
    os_name=$(echo "$os_info" | sed -n 's/\(.*\) (Linux \(.*\) \(.*\))/\1/p')
    kernel=$(echo "$os_info" | sed -n 's/.* (Linux \(.*\) \(.*\))/\1/p')
    arch=$(echo "$os_info" | sed -n 's/.* (Linux \(.*\) \(.*\))/\2/p')
    [ -z "$os_name" ] && os_name="N/A"
    [ -z "$kernel" ] && kernel="N/A"
    [ -z "$arch" ]   && arch="N/A"

    local cpu_model cpu_cores
    cpu_model=$(echo "$cpu_info" | sed 's/ (\(.*\) cores\?)/\1/')
    cpu_cores=$(echo "$cpu_info" | sed -n 's/.*(\(.*\) cores\?)/\1/p')
    [ -z "$cpu_cores" ] && cpu_cores="N/A"

    local ram_json
    ram_json=$(jq -n \
        --arg total "$total_bytes" \
        --arg used "$used_bytes" \
        --arg free "$free_bytes" \
        --arg unit "$unit" \
        '{total: $total, used: $used, free: $free, unit: $unit}')

    local disk_json="[]"
    if command -v lsblk &>/dev/null; then
        disk_json=$(lsblk -Jdno NAME,SIZE,MODEL 2>/dev/null | jq '[.blockdevices[] | {device: ("/dev/" + .name), size: .size, model: .model}]' 2>/dev/null) || disk_json="[]"
    fi

    local mounts_json="[]"
    if command -v df &>/dev/null; then
        mounts_json=$(df -P -T 2>/dev/null | grep -v -E '^(tmpfs|devtmpfs|overlay|squashfs)' | tail -n +2 | \
            jq -R -s '
              [ split("\n")[] | select(length>0) | split(" ") 
                | {device: .[0], fstype: .[1], total: .[2], used: .[3], avail: .[4], mountpoint: .[5]} ]
            ' 2>/dev/null) || mounts_json="[]"
    fi

    local users_json="[]"
    users_json=$(while IFS=: read -r user pass uid gid gecos home shell; do
        if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] || [ "$user" = "root" ]; then
            local grps
            grps=$(id -Gn "$user" 2>/dev/null | tr ' ' ',')
            jq -n --arg u "$user" --arg g "$grps" '{username: $u, groups: $g}'
        fi
    done < /etc/passwd | jq -s '.')
    [ -z "$users_json" ] && users_json="[]"

    jq -n \
        --argjson os "$(jq -n --arg name "$os_name" --arg kernel "$kernel" --arg arch "$arch" \
            '{name: $name, kernel: $kernel, arch: $arch}')" \
        --argjson cpu "$(jq -n --arg model "$cpu_model" --arg cores "$cpu_cores" \
            '{model: $model, cores: $cores}')" \
        --argjson ram "$ram_json" \
        --argjson disks "$disk_json" \
        --argjson mounts "$mounts_json" \
        --argjson users "$users_json" \
        '{os: $os, cpu: $cpu, ram: $ram, disks: $disks, mounts: $mounts, users: $users}'
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    if [ "${1:-}" = "-j" ] || [ "${1:-}" = "--json" ]; then
        if ! command -v jq &>/dev/null; then
            echo "Error: 'jq' is required for JSON output but not found." >&2
            exit 1
        fi
        output_json
    else
        output_clean
    fi
}

main "$@"
