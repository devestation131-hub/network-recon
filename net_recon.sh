#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# net_recon.sh — Network Reconnaissance Sweep
# Author : Zachari Higgins
# Performs host discovery, port scanning, OS fingerprinting,
# and service enumeration on a target subnet. Outputs HTML report.
#
# Usage:
#   ./net_recon.sh -t 192.168.1.0/24
#   ./net_recon.sh -t 10.0.0.0/24 -o report.html -p "22,80,443,3389"
#   ./net_recon.sh -t 192.168.1.1 --quick
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; RESET='\033[0m'; BOLD='\033[1m'

# Defaults
TARGET=""
OUTPUT="recon_$(date +%Y%m%d_%H%M%S).html"
PORTS="22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443"
QUICK=false
LOGFILE="/tmp/net_recon_$$.log"

usage() {
    echo -e "${CYAN}Network Reconnaissance Sweep${RESET}"
    echo ""
    echo "Usage: $0 -t TARGET [options]"
    echo ""
    echo "Options:"
    echo "  -t, --target    Target IP or CIDR range (required)"
    echo "  -o, --output    Output HTML report path (default: recon_DATE.html)"
    echo "  -p, --ports     Comma-separated port list (default: top 20)"
    echo "  --quick         Quick scan — ping sweep only, no port scan"
    echo "  -h, --help      Show this help"
    exit 0
}

log() { echo -e "$1" | tee -a "$LOGFILE"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target) TARGET="$2"; shift 2;;
        -o|--output) OUTPUT="$2"; shift 2;;
        -p|--ports)  PORTS="$2"; shift 2;;
        --quick)     QUICK=true; shift;;
        -h|--help)   usage;;
        *) echo "Unknown option: $1"; usage;;
    esac
done

[[ -z "$TARGET" ]] && { echo -e "${RED}Error: Target required. Use -t${RESET}"; usage; }

# Check dependencies
for cmd in ping nmap arp; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${YELLOW}Warning: $cmd not found. Some features may be limited.${RESET}"
    fi
done

echo ""
log "${BOLD}═══════════════════════════════════════════════${RESET}"
log "${CYAN} Network Reconnaissance Sweep${RESET}"
log "${CYAN} Target: $TARGET${RESET}"
log "${CYAN} Ports:  $PORTS${RESET}"
log "${CYAN} Output: $OUTPUT${RESET}"
log "${CYAN} Time:   $(date)${RESET}"
log "${BOLD}═══════════════════════════════════════════════${RESET}"
echo ""

LIVE_HOSTS=()
SCAN_RESULTS=()
START_TIME=$(date +%s)

# ─── Phase 1: Host Discovery ─────────────────────────────────────────────
log "${BOLD}[Phase 1] Host Discovery — Ping Sweep${RESET}"

if command -v nmap &>/dev/null; then
    # Use nmap for reliable host discovery
    while IFS= read -r line; do
        ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+')
        if [[ -n "$ip" ]]; then
            LIVE_HOSTS+=("$ip")
            log "  ${GREEN}[+] Live: $ip${RESET}"
        fi
    done < <(nmap -sn "$TARGET" 2>/dev/null | grep "Nmap scan report")
else
    # Fallback to ping
    if [[ "$TARGET" == *"/"* ]]; then
        # CIDR range — extract base and iterate
        BASE=$(echo "$TARGET" | cut -d'/' -f1 | cut -d'.' -f1-3)
        for i in $(seq 1 254); do
            ip="$BASE.$i"
            if ping -c 1 -W 1 "$ip" &>/dev/null; then
                LIVE_HOSTS+=("$ip")
                log "  ${GREEN}[+] Live: $ip${RESET}"
            fi
        done
    else
        if ping -c 1 -W 2 "$TARGET" &>/dev/null; then
            LIVE_HOSTS+=("$TARGET")
            log "  ${GREEN}[+] Live: $TARGET${RESET}"
        fi
    fi
fi

log "\n  ${BOLD}Found ${#LIVE_HOSTS[@]} live host(s)${RESET}\n"

if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
    log "${RED}No live hosts found. Exiting.${RESET}"
    exit 1
fi

if $QUICK; then
    log "${YELLOW}Quick mode — skipping port scan${RESET}"
else
    # ─── Phase 2: Port Scanning ──────────────────────────────────────────
    log "${BOLD}[Phase 2] Port Scanning${RESET}"
    
    for host in "${LIVE_HOSTS[@]}"; do
        log "\n  ${CYAN}Scanning $host...${RESET}"
        
        if command -v nmap &>/dev/null; then
            scan_output=$(nmap -sV -p "$PORTS" --open "$host" 2>/dev/null)
            
            while IFS= read -r line; do
                if [[ "$line" =~ ^[0-9]+/tcp ]]; then
                    port=$(echo "$line" | awk '{print $1}')
                    state=$(echo "$line" | awk '{print $2}')
                    service=$(echo "$line" | awk '{$1=$2=""; print $0}' | xargs)
                    log "    ${GREEN}$port${RESET}  $state  $service"
                    SCAN_RESULTS+=("$host|$port|$state|$service")
                fi
            done <<< "$scan_output"
            
            # OS detection
            os_line=$(echo "$scan_output" | grep -i "OS details\|Service Info: OS" | head -1)
            if [[ -n "$os_line" ]]; then
                log "    ${YELLOW}OS: $os_line${RESET}"
                SCAN_RESULTS+=("$host|OS|detected|$os_line")
            fi
        else
            # Fallback: bash TCP scan
            IFS=',' read -ra port_list <<< "$PORTS"
            for port in "${port_list[@]}"; do
                if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
                    log "    ${GREEN}$port/tcp  open${RESET}"
                    SCAN_RESULTS+=("$host|$port/tcp|open|unknown")
                fi
            done
        fi
    done
fi

# ─── Phase 3: ARP Table ──────────────────────────────────────────────────
log "\n${BOLD}[Phase 3] ARP Table${RESET}"
if command -v arp &>/dev/null; then
    arp -a 2>/dev/null | head -20 | while read -r line; do
        log "  $line"
    done
fi

# ─── Phase 4: Generate HTML Report ───────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

log "\n${BOLD}[Phase 4] Generating HTML Report${RESET}"

HOST_ROWS=""
for host in "${LIVE_HOSTS[@]}"; do
    host_ports=""
    while IFS='|' read -r h port state service; do
        if [[ "$h" == "$host" && "$port" != "OS" ]]; then
            host_ports+="<tr><td>$port</td><td style='color:#00ff88;'>$state</td><td>$service</td></tr>"
        fi
    done < <(printf '%s\n' "${SCAN_RESULTS[@]}" 2>/dev/null)
    
    HOST_ROWS+="
    <div style='background:#12131a;border:1px solid #1a1c26;border-radius:8px;padding:16px;margin-bottom:12px;'>
        <h3 style='color:#00ff88;margin:0 0 10px;'>$host</h3>
        <table style='width:100%;'><thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead>
        <tbody>$host_ports</tbody></table>
    </div>"
done

cat > "$OUTPUT" << HTMLEOF
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Network Recon Report</title>
<style>
body{font-family:'Segoe UI',monospace;background:#0d0e14;color:#c8ccd4;padding:40px;max-width:900px;margin:0 auto;}
h1{color:#00ff88;} h3{color:#6699ff;}
table{width:100%;border-collapse:collapse;margin:10px 0;}
th{background:#1a1c26;color:#888;padding:8px;text-align:left;font-size:12px;text-transform:uppercase;}
td{padding:6px 8px;border-bottom:1px solid #1a1c26;font-size:13px;}
.stat{display:inline-block;background:#12131a;border:1px solid #1a1c26;border-radius:8px;padding:16px 24px;margin:5px;text-align:center;}
.stat .num{font-size:28px;font-weight:700;color:#00ff88;} .stat .label{font-size:10px;color:#666;text-transform:uppercase;}
</style></head><body>
<h1>🔍 Network Recon Report</h1>
<p style="color:#666;">Target: $TARGET | Date: $(date) | Duration: ${ELAPSED}s</p>
<div style="margin:20px 0;">
    <div class="stat"><div class="num">${#LIVE_HOSTS[@]}</div><div class="label">Live Hosts</div></div>
    <div class="stat"><div class="num">${#SCAN_RESULTS[@]}</div><div class="label">Open Ports</div></div>
    <div class="stat"><div class="num">${ELAPSED}s</div><div class="label">Scan Time</div></div>
</div>
<h2 style="color:#888;">Host Details</h2>
$HOST_ROWS
<p style="color:#333;margin-top:30px;font-size:11px;">Generated by net_recon.sh — Zachari Higgins</p>
</body></html>
HTMLEOF

log "  ${GREEN}[+] Report saved: $OUTPUT${RESET}"
log "\n${BOLD}═══════════════════════════════════════════════${RESET}"
log "${GREEN} Recon complete — ${#LIVE_HOSTS[@]} hosts, ${#SCAN_RESULTS[@]} findings, ${ELAPSED}s${RESET}"
log "${BOLD}═══════════════════════════════════════════════${RESET}"

rm -f "$LOGFILE"
