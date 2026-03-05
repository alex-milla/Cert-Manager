#!/bin/bash
# ============================================================
#  Certificate Manager v1.3 - Local cert store + auto-refresh
#  Author: Alex Millà - alexmilla.dev
#  Expected path: /opt/cert-monitor/cert_manager.sh
#
#  Usage:
#    ./cert_manager.sh              → default refresh (300s = 5 min)
#    ./cert_manager.sh --refresh 60 → refresh every 60 seconds
#    ./cert_manager.sh --refresh 0  → no auto-refresh (manual only)
#
#  New in v1.3:
#    - Local certificate store (certs/ directory)
#    - Import from: local path, network share (CIFS/NFS), URL
#    - PFX/P12 auto-extraction (prompts password once)
#    - DER auto-conversion to PEM
#    - Dashboard shows local certs alongside remote servers
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FILE="${SCRIPT_DIR}/servers.txt"
REFRESH_FILE="${SCRIPT_DIR}/.refresh_interval"
CERT_STORE="${SCRIPT_DIR}/certs"
MOUNT_DIR="${SCRIPT_DIR}/mnt"

[ ! -f "$FILE" ] && echo "# host:port:type" > "$FILE"
[ ! -d "$CERT_STORE" ] && mkdir -p "$CERT_STORE"
[ ! -d "$MOUNT_DIR" ] && mkdir -p "$MOUNT_DIR"

# --- Refresh interval ---
DEFAULT_REFRESH=300

if [[ "$1" == "--refresh" && -n "$2" ]]; then
    REFRESH="$2"
elif [ -f "$REFRESH_FILE" ]; then
    REFRESH=$(cat "$REFRESH_FILE")
else
    REFRESH=$DEFAULT_REFRESH
fi

# --- Colors ---
RED='\033[1;31m'
ORANGE='\033[1;33m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
DIM='\033[0;37m'
BOLD='\033[1m'
RESET='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_ORANGE='\033[43m'
MAGENTA='\033[1;35m'

# --- Box drawing ---
H="─"; V="│"; TL="┌"; TR="┐"; BL="└"; BR="┘"
LT="├"; RT="┤"; HD="┬"; HU="┴"; CR="┼"

repeat_char() { printf "%0.s$1" $(seq 1 "$2"); }

# --- Column widths ---
W_STATUS=12
W_HOST=45
W_DAYS=10
W_EXPIRY=28
WARN_DAYS=30
CRIT_DAYS=15

# ============================================================
#  HELPER: Format interval
# ============================================================
format_interval() {
    local S=$1
    if [ "$S" -eq 0 ]; then echo "manual"
    elif [ "$S" -lt 60 ]; then echo "${S}s"
    elif [ "$S" -lt 3600 ]; then echo "$((S / 60))m"
    else
        local HH=$((S / 3600)); local MM=$(( (S % 3600) / 60 ))
        if [ "$MM" -gt 0 ]; then echo "${HH}h ${MM}m"; else echo "${HH}h"; fi
    fi
}

# ============================================================
#  HELPER: Get icon by type
# ============================================================
get_icon() {
    case "$1" in
        IIS)       echo "🖥️" ;;
        APACHE)    echo "🪶" ;;
        NGINX)     echo "🟢" ;;
        TOMCAT)    echo "🐱" ;;
        APPLIANCE) echo "🔧" ;;
        PROXY)     echo "🔀" ;;
        LOCAL)     echo "📁" ;;
        *)         echo "📡" ;;
    esac
}

# ============================================================
#  HELPER: Detect cert format and read expiry from local file
#  Returns: "SUBJECT|ISSUER|START|END|SERIAL|SIG|BITS" or empty
# ============================================================
read_local_cert() {
    local CERTFILE="$1"
    local INFORM=""

    # Detect format
    if file "$CERTFILE" 2>/dev/null | grep -qi "PEM\|ASCII\|text"; then
        INFORM="PEM"
    elif file "$CERTFILE" 2>/dev/null | grep -qi "data\|DER\|ASN"; then
        INFORM="DER"
    else
        # Try PEM first, then DER
        if openssl x509 -in "$CERTFILE" -inform PEM -noout -enddate 2>/dev/null | grep -q "notAfter"; then
            INFORM="PEM"
        elif openssl x509 -in "$CERTFILE" -inform DER -noout -enddate 2>/dev/null | grep -q "notAfter"; then
            INFORM="DER"
        else
            return 1
        fi
    fi

    local SUBJECT ISSUER START END SERIAL SIG BITS
    SUBJECT=$(openssl x509 -in "$CERTFILE" -inform "$INFORM" -noout -subject 2>/dev/null | sed 's/subject=//')
    ISSUER=$(openssl x509 -in "$CERTFILE" -inform "$INFORM" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    START=$(openssl x509 -in "$CERTFILE" -inform "$INFORM" -noout -startdate 2>/dev/null | cut -d= -f2)
    END=$(openssl x509 -in "$CERTFILE" -inform "$INFORM" -noout -enddate 2>/dev/null | cut -d= -f2)
    SERIAL=$(openssl x509 -in "$CERTFILE" -inform "$INFORM" -noout -serial 2>/dev/null | cut -d= -f2)
    SIG=$(openssl x509 -in "$CERTFILE" -inform "$INFORM" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | xargs)
    BITS=$(openssl x509 -in "$CERTFILE" -inform "$INFORM" -noout -text 2>/dev/null | grep "Public-Key" | head -1 | xargs)

    [ -z "$END" ] && return 1
    echo "${SUBJECT}|${ISSUER}|${START}|${END}|${SERIAL}|${SIG}|${BITS}"
}

# ============================================================
#  HELPER: Import a certificate file into the store
#  Handles: PEM, DER, CRT, CER, PFX/P12
# ============================================================
import_cert_file() {
    local SRC="$1"
    local BASENAME
    BASENAME=$(basename "$SRC")
    local EXT="${BASENAME##*.}"
    EXT=$(echo "$EXT" | tr '[:upper:]' '[:lower:]')
    local DEST_NAME="${BASENAME%.*}.pem"

    echo ""

    # PFX / P12 → extract public cert only
    if [[ "$EXT" == "pfx" || "$EXT" == "p12" ]]; then
        echo -e "  ${ORANGE}⚠ PFX/P12 detected — password required to extract public certificate${RESET}"
        echo -e "  ${DIM}(Only the public certificate will be stored, NOT the private key)${RESET}"
        echo ""
        echo -ne "  ${WHITE}PFX password${RESET}: "
        read -rs PFX_PASS
        echo ""

        echo -ne "  ${DIM}Extracting certificate...${RESET} "
        if openssl pkcs12 -in "$SRC" -clcerts -nokeys -passin "pass:${PFX_PASS}" \
            -out "${CERT_STORE}/${DEST_NAME}" 2>/dev/null; then
            echo -e "${GREEN}✔${RESET}"
            echo -e "  ${GREEN}${BOLD}✔ Imported: ${DEST_NAME}${RESET} ${DIM}(public cert only, no private key)${RESET}"
            return 0
        else
            echo -e "${RED}✗ Failed${RESET}"
            echo -e "  ${RED}Wrong password or corrupted PFX file${RESET}"
            return 1
        fi
    fi

    # DER → convert to PEM
    if [[ "$EXT" == "der" ]] || (file "$SRC" 2>/dev/null | grep -qi "data\|DER\|ASN" && ! file "$SRC" 2>/dev/null | grep -qi "PEM\|ASCII\|text"); then
        echo -ne "  ${DIM}DER format detected, converting to PEM...${RESET} "
        if openssl x509 -in "$SRC" -inform DER -out "${CERT_STORE}/${DEST_NAME}" -outform PEM 2>/dev/null; then
            echo -e "${GREEN}✔${RESET}"
            echo -e "  ${GREEN}${BOLD}✔ Imported: ${DEST_NAME}${RESET}"
            return 0
        else
            echo -e "${RED}✗ Failed${RESET}"
            return 1
        fi
    fi

    # PEM / CRT / CER → validate and copy
    echo -ne "  ${DIM}Validating certificate...${RESET} "
    if openssl x509 -in "$SRC" -noout -enddate 2>/dev/null | grep -q "notAfter"; then
        cp "$SRC" "${CERT_STORE}/${DEST_NAME}" 2>/dev/null
        echo -e "${GREEN}✔${RESET}"
        echo -e "  ${GREEN}${BOLD}✔ Imported: ${DEST_NAME}${RESET}"
        return 0
    else
        echo -e "${RED}✗ Not a valid certificate${RESET}"
        return 1
    fi
}

# ============================================================
#  MAIN DASHBOARD
# ============================================================
draw_dashboard() {
    clear

    local COUNT_OK=0 COUNT_WARN=0 COUNT_CRIT=0 COUNT_ERROR=0 TOTAL=0

    # --- Banner ---
    echo ""
    echo -e "${CYAN}${BOLD}  ╔════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}  ║                              🔒  CERTIFICATE MONITOR v1.3  🔒                                ║${RESET}"
    echo -e "${CYAN}${BOLD}  ║                              $(date '+%Y-%m-%d %H:%M:%S')                                                ║${RESET}"
    echo -e "${CYAN}${BOLD}  ╚════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"

    # --- Collect remote servers ---
    TYPES=$(grep -v '^#' "$FILE" | grep -v '^$' | cut -d: -f3 | sort -u | xargs)

    declare -gA TYPE_DATA=()

    local HAS_REMOTE=0 HAS_LOCAL=0

    if [ -n "$TYPES" ]; then
        HAS_REMOTE=1
        echo ""
        echo -ne "  ${DIM}Checking remote certificates"

        while IFS=: read -r HOST PORT TYPE; do
            [[ -z "$HOST" || "$HOST" == \#* ]] && continue
            PORT=${PORT:-443}
            TYPE=$(echo "${TYPE:-OTHER}" | tr '[:lower:]' '[:upper:]' | xargs)
            TOTAL=$((TOTAL + 1))
            echo -ne "."

            EXPIRY=$(echo | timeout 5 openssl s_client -servername "$HOST" \
                -connect "$HOST:$PORT" 2>/dev/null \
                | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

            if [ -z "$EXPIRY" ]; then
                ENTRY="ERROR|${HOST}:${PORT}|0|Could not connect"
                COUNT_ERROR=$((COUNT_ERROR + 1))
            else
                DAYS=$(( ( $(date -d "$EXPIRY" +%s) - $(date +%s) ) / 86400 ))
                if [ "$DAYS" -le 0 ]; then COUNT_CRIT=$((COUNT_CRIT + 1))
                elif [ "$DAYS" -le "$CRIT_DAYS" ]; then COUNT_CRIT=$((COUNT_CRIT + 1))
                elif [ "$DAYS" -le "$WARN_DAYS" ]; then COUNT_WARN=$((COUNT_WARN + 1))
                else COUNT_OK=$((COUNT_OK + 1))
                fi
                ENTRY="DATA|${HOST}:${PORT}|${DAYS}|${EXPIRY}"
            fi

            TYPE_DATA["$TYPE"]+="${ENTRY}"$'\n'
        done < "$FILE"

        echo -e " ${GREEN}✔${RESET}"
    fi

    # --- Collect local certificates ---
    LOCAL_ENTRIES=""
    LOCAL_COUNT=0

    if [ -d "$CERT_STORE" ]; then
        CERT_FILES=$(find "$CERT_STORE" -maxdepth 1 -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der" \) 2>/dev/null | sort)

        if [ -n "$CERT_FILES" ]; then
            if [ $HAS_REMOTE -eq 0 ]; then
                echo ""
            fi
            echo -ne "  ${DIM}Checking local certificates"

            while IFS= read -r CERTFILE; do
                [ -z "$CERTFILE" ] && continue
                LOCAL_COUNT=$((LOCAL_COUNT + 1))
                TOTAL=$((TOTAL + 1))
                echo -ne "."

                FNAME=$(basename "$CERTFILE")

                END=$(openssl x509 -in "$CERTFILE" -noout -enddate 2>/dev/null | cut -d= -f2)
                if [ -z "$END" ]; then
                    # Try DER
                    END=$(openssl x509 -in "$CERTFILE" -inform DER -noout -enddate 2>/dev/null | cut -d= -f2)
                fi

                if [ -z "$END" ]; then
                    LOCAL_ENTRIES+="ERROR|${FNAME}|0|Could not read"$'\n'
                    COUNT_ERROR=$((COUNT_ERROR + 1))
                else
                    DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
                    if [ "$DAYS" -le 0 ]; then COUNT_CRIT=$((COUNT_CRIT + 1))
                    elif [ "$DAYS" -le "$CRIT_DAYS" ]; then COUNT_CRIT=$((COUNT_CRIT + 1))
                    elif [ "$DAYS" -le "$WARN_DAYS" ]; then COUNT_WARN=$((COUNT_WARN + 1))
                    else COUNT_OK=$((COUNT_OK + 1))
                    fi
                    LOCAL_ENTRIES+="DATA|${FNAME}|${DAYS}|${END}"$'\n'
                fi
            done <<< "$CERT_FILES"

            HAS_LOCAL=1
            echo -e " ${GREEN}✔${RESET}"
        fi
    fi

    # --- Empty check ---
    if [ $HAS_REMOTE -eq 0 ] && [ $HAS_LOCAL -eq 0 ]; then
        echo ""
        echo -e "  ${ORANGE}⚠  No servers or local certificates found.${RESET}"
        echo -e "  ${DIM}   Use option 1 to add a remote server or 8 to import a certificate.${RESET}"
        echo ""
        return
    fi

    # --- Summary ---
    echo ""
    echo -e "  ${WHITE}${BOLD}SUMMARY${RESET}  ${DIM}(thresholds: warning ≤${WARN_DAYS}d | alert ≤${CRIT_DAYS}d)${RESET}"
    echo ""
    echo -e "  ${BG_GREEN}${WHITE}${BOLD}  ✔ OK: ${COUNT_OK}  ${RESET}  ${BG_ORANGE}${WHITE}${BOLD}  ● WARN: ${COUNT_WARN}  ${RESET}  ${BG_RED}${WHITE}${BOLD}  ✗ ALERT: ${COUNT_CRIT}  ${RESET}  ${DIM}  ✗ ERROR: ${COUNT_ERROR}  ${RESET}  ${DIM}│ Total: ${TOTAL}${RESET}"

    # ---- Helper: draw a table from entries ----
    draw_table() {
        local ENTRIES="$1"

        echo -e "  ${DIM}${TL}$(repeat_char "$H" $((W_STATUS+1)))${HD}$(repeat_char "$H" $((W_HOST+1)))${HD}$(repeat_char "$H" $((W_DAYS+1)))${HD}$(repeat_char "$H" $((W_EXPIRY+1)))${TR}${RESET}"
        echo -e "  ${DIM}${V}${RESET}${WHITE}${BOLD} $(printf "%-${W_STATUS}s" "STATUS")${RESET}${DIM}${V}${RESET}${WHITE}${BOLD} $(printf "%-${W_HOST}s" "NAME")${RESET}${DIM}${V}${RESET}${WHITE}${BOLD} $(printf "%-${W_DAYS}s" "DAYS")${RESET}${DIM}${V}${RESET}${WHITE}${BOLD} $(printf "%-${W_EXPIRY}s" "EXPIRATION DATE")${RESET}${DIM}${V}${RESET}"
        echo -e "  ${DIM}${LT}$(repeat_char "$H" $((W_STATUS+1)))${CR}$(repeat_char "$H" $((W_HOST+1)))${CR}$(repeat_char "$H" $((W_DAYS+1)))${CR}$(repeat_char "$H" $((W_EXPIRY+1)))${RT}${RESET}"

        while IFS= read -r LINE; do
            [ -z "$LINE" ] && continue
            IFS='|' read -r S NAME DAYS EXP <<< "$LINE"

            if [ "$S" = "ERROR" ]; then
                C="$RED"; TAG=" ✗ ERROR"; DD="---"
            elif [ "$DAYS" -le 0 ]; then
                C="$RED"; TAG=" ✗ EXPIRED"; DD="$DAYS"
            elif [ "$DAYS" -le "$CRIT_DAYS" ]; then
                C="$RED"; TAG=" ▲ ALERT"; DD="$DAYS"
            elif [ "$DAYS" -le "$WARN_DAYS" ]; then
                C="$ORANGE"; TAG=" ● WARNING"; DD="$DAYS"
            else
                C="$GREEN"; TAG=" ✔ OK"; DD="$DAYS"
            fi

            echo -e "  ${DIM}${V}${RESET}${C}$(printf " %-${W_STATUS}s" "$TAG")${RESET}${DIM}${V}${RESET} $(printf "%-${W_HOST}s" "$NAME")${DIM}${V}${RESET}${C}$(printf " %-${W_DAYS}s" "$DD")${RESET}${DIM}${V}${RESET}${DIM} $(printf "%-${W_EXPIRY}s" "$EXP")${RESET}${DIM}${V}${RESET}"

        done <<< "$ENTRIES"

        echo -e "  ${DIM}${BL}$(repeat_char "$H" $((W_STATUS+1)))${HU}$(repeat_char "$H" $((W_HOST+1)))${HU}$(repeat_char "$H" $((W_DAYS+1)))${HU}$(repeat_char "$H" $((W_EXPIRY+1)))${BR}${RESET}"
    }

    # --- Remote server tables by type ---
    for T in $TYPES; do
        [ -z "${TYPE_DATA[$T]}" ] && continue
        ICON=$(get_icon "$T")

        echo ""
        echo -e "${CYAN}${BOLD}  ${ICON}  ${T} $(repeat_char "─" $((85 - ${#T})))${RESET}"
        echo ""
        draw_table "${TYPE_DATA[$T]}"
    done

    # --- Local certificates table ---
    if [ -n "$LOCAL_ENTRIES" ]; then
        echo ""
        echo -e "${MAGENTA}${BOLD}  📁  LOCAL CERTIFICATES $(repeat_char "─" 67)${RESET}"
        echo -e "  ${DIM}Store: ${CERT_STORE}/ (${LOCAL_COUNT} files)${RESET}"
        echo ""
        draw_table "$LOCAL_ENTRIES"
    fi

    echo ""
    echo -e "  ${DIM}Generated: $(hostname) | OpenSSL $(openssl version 2>/dev/null | cut -d' ' -f2)${RESET}"
}

# ============================================================
#  MENU
# ============================================================
draw_menu() {
    local REFRESH_LABEL
    REFRESH_LABEL=$(format_interval "$REFRESH")

    echo ""
    echo -e "  ${DIM}$(repeat_char "─" 96)${RESET}"

    if [ "$REFRESH" -gt 0 ]; then
        local NEXT_REFRESH
        NEXT_REFRESH=$(date -d "+${REFRESH} seconds" '+%H:%M:%S' 2>/dev/null || echo "---")
        echo -e "  ${DIM}⏱  Auto-refresh: every ${WHITE}${REFRESH_LABEL}${RESET}${DIM} │ Next: ${NEXT_REFRESH} │ Press any key at any time to interact${RESET}"
    else
        echo -e "  ${DIM}⏱  Auto-refresh: ${WHITE}disabled${RESET}${DIM} │ Press 5 to refresh manually${RESET}"
    fi

    echo ""
    echo -e "  ${WHITE}${BOLD}SERVERS${RESET}                                              ${WHITE}${BOLD}CERT STORE${RESET}"
    echo -e "  ${GREEN}1)${RESET} Add server   ${GREEN}2)${RESET} Inventory   ${GREEN}3)${RESET} Remove server    ${GREEN}8)${RESET} Import certificate   ${GREEN}9)${RESET} Remove certificate"
    echo ""
    echo -e "  ${WHITE}${BOLD}TOOLS${RESET}"
    echo -e "  ${GREEN}4)${RESET} Quick check  ${GREEN}5)${RESET} Refresh     ${GREEN}6)${RESET} Export report    ${GREEN}7)${RESET} ⏱ Set interval       ${RED}0)${RESET} Exit"
    echo ""
    echo -ne "  ${CYAN}▸${RESET} "
}

# ============================================================
#  7) CHANGE REFRESH INTERVAL
# ============================================================
change_refresh() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}  ── Configure auto-refresh ──${RESET}"
    echo ""
    echo -e "  ${DIM}Current: $(format_interval "$REFRESH")${RESET}"
    echo ""
    echo -e "  ${WHITE}${BOLD}Choose an interval:${RESET}"
    echo ""
    echo -e "  ${GREEN}1)${RESET}  30 seconds       ${DIM}(testing)${RESET}"
    echo -e "  ${GREEN}2)${RESET}   1 minute"
    echo -e "  ${GREEN}3)${RESET}   5 minutes        ${DIM}(default)${RESET}"
    echo -e "  ${GREEN}4)${RESET}  15 minutes"
    echo -e "  ${GREEN}5)${RESET}  30 minutes"
    echo -e "  ${GREEN}6)${RESET}   1 hour"
    echo -e "  ${GREEN}7)${RESET}   6 hours"
    echo -e "  ${GREEN}8)${RESET}  12 hours"
    echo -e "  ${GREEN}9)${RESET}  24 hours"
    echo -e "  ${GREEN}C)${RESET}  Custom            ${DIM}(enter seconds manually)${RESET}"
    echo -e "  ${GREEN}0)${RESET}  Disable           ${DIM}(manual only)${RESET}"
    echo ""
    echo -ne "  ${CYAN}▸${RESET} "
    read -r CHOICE

    case "$CHOICE" in
        1) REFRESH=30 ;; 2) REFRESH=60 ;; 3) REFRESH=300 ;;
        4) REFRESH=900 ;; 5) REFRESH=1800 ;; 6) REFRESH=3600 ;;
        7) REFRESH=21600 ;; 8) REFRESH=43200 ;; 9) REFRESH=86400 ;;
        [cC])
            echo ""
            echo -ne "  ${WHITE}Seconds between each refresh${RESET}: "
            read -r CUSTOM
            if [[ "$CUSTOM" =~ ^[0-9]+$ ]]; then REFRESH=$CUSTOM
            else echo -e "  ${RED}Invalid value, keeping current setting${RESET}"; sleep 1; return; fi
            ;;
        0) REFRESH=0 ;; *) return ;;
    esac

    echo "$REFRESH" > "$REFRESH_FILE"
    echo ""
    if [ "$REFRESH" -eq 0 ]; then echo -e "  ${GREEN}✔ Auto-refresh disabled${RESET}"
    else echo -e "  ${GREEN}✔ Auto-refresh set to: every $(format_interval "$REFRESH")${RESET}"; fi
    sleep 1
}

# ============================================================
#  1) ADD SERVER
# ============================================================
add_server() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}  ── Add new server ──${RESET}"
    echo ""

    echo -ne "  ${WHITE}Server URL or IP${RESET} (e.g. web01.domain.com): "
    read -r HOST
    HOST=$(echo "$HOST" | sed 's|https\?://||' | sed 's|/.*||')

    if [ -z "$HOST" ]; then
        echo -e "\n  ${RED}✗ No server specified${RESET}"; sleep 1; return
    fi

    echo -ne "  ${WHITE}Port${RESET} [443]: "
    read -r PORT; PORT=${PORT:-443}

    echo ""
    echo -e "  ${WHITE}${BOLD}Web server type:${RESET}"
    echo ""
    echo -e "  ${GREEN}1)${RESET} IIS        ${GREEN}2)${RESET} Apache     ${GREEN}3)${RESET} Nginx"
    echo -e "  ${GREEN}4)${RESET} Tomcat     ${GREEN}5)${RESET} Appliance  ${GREEN}6)${RESET} Proxy"
    echo -e "  ${GREEN}7)${RESET} Other"
    echo ""
    echo -ne "  ${CYAN}▸${RESET} Type: "
    read -r TYPE_CHOICE

    case "$TYPE_CHOICE" in
        1) TYPE="IIS" ;; 2) TYPE="APACHE" ;; 3) TYPE="NGINX" ;;
        4) TYPE="TOMCAT" ;; 5) TYPE="APPLIANCE" ;; 6) TYPE="PROXY" ;;
        7) echo -ne "  Enter type: "; read -r TYPE; TYPE=$(echo "$TYPE" | tr '[:lower:]' '[:upper:]' | xargs) ;;
        *) TYPE="OTHER" ;;
    esac

    if grep -q "^${HOST}:${PORT}:" "$FILE" 2>/dev/null; then
        echo -e "\n  ${ORANGE}⚠ ${HOST}:${PORT} already exists in inventory${RESET}"; sleep 2; return
    fi

    echo ""
    echo -ne "  ${DIM}Testing connection to ${HOST}:${PORT}...${RESET} "

    EXPIRY=$(echo | timeout 5 openssl s_client -servername "$HOST" \
        -connect "$HOST:$PORT" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

    if [ -n "$EXPIRY" ]; then
        DAYS=$(( ( $(date -d "$EXPIRY" +%s) - $(date +%s) ) / 86400 ))
        echo -e "${GREEN}✔ OK${RESET} ${DIM}(expires in ${DAYS} days)${RESET}"
    else
        echo -e "${ORANGE}⚠ Could not verify${RESET}"
    fi

    echo "${HOST}:${PORT}:${TYPE}" >> "$FILE"
    echo -e "  ${GREEN}${BOLD}✔ Added: ${HOST}:${PORT} [${TYPE}]${RESET}"

    echo ""
    echo -ne "  Add another? (y/N): "
    read -r AGAIN
    [[ "$AGAIN" =~ ^[yY]$ ]] && add_server
}

# ============================================================
#  2) VIEW INVENTORY
# ============================================================
list_servers() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}  ── Registered servers & certificates ──${RESET}"
    echo ""

    # Remote
    TYPES=$(grep -v '^#' "$FILE" | grep -v '^$' | cut -d: -f3 | sort -u)
    local HAS_ITEMS=0

    if [ -n "$TYPES" ]; then
        HAS_ITEMS=1
        echo -e "  ${WHITE}${BOLD}── REMOTE SERVERS ──${RESET}"
        echo ""
        for T in $TYPES; do
            echo -e "  ${WHITE}${BOLD}[$T]${RESET}"
            grep -v '^#' "$FILE" | grep -v '^$' | while IFS=: read -r SH SP STP; do
                STP=$(echo "$STP" | xargs)
                [ "$STP" = "$T" ] && echo -e "    ${DIM}•${RESET} ${SH}:${SP}"
            done
            echo ""
        done
    fi

    # Local
    CERT_FILES=$(find "$CERT_STORE" -maxdepth 1 -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der" \) 2>/dev/null | sort)
    if [ -n "$CERT_FILES" ]; then
        HAS_ITEMS=1
        echo -e "  ${WHITE}${BOLD}── LOCAL CERTIFICATES ──${RESET}"
        echo -e "  ${DIM}Store: ${CERT_STORE}/${RESET}"
        echo ""
        while IFS= read -r CF; do
            [ -z "$CF" ] && continue
            echo -e "    ${DIM}•${RESET} $(basename "$CF")"
        done <<< "$CERT_FILES"
        echo ""
    fi

    if [ $HAS_ITEMS -eq 0 ]; then
        echo -e "  ${DIM}Empty. Use option 1 (servers) or 8 (certificates) to add.${RESET}"
    fi

    REMOTE_TOTAL=$(grep -v '^#' "$FILE" | grep -v '^$' | wc -l)
    LOCAL_TOTAL=$(echo "$CERT_FILES" | grep -c -v '^$' 2>/dev/null || echo 0)
    echo ""
    echo -e "  ${DIM}Remote: ${REMOTE_TOTAL} | Local: ${LOCAL_TOTAL}${RESET}"
    echo ""
    read -rsp "  Press Enter to go back to dashboard..."
}

# ============================================================
#  3) REMOVE SERVER
# ============================================================
delete_server() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}  ── Remove server ──${RESET}"
    echo ""

    local i=0
    declare -a LINES=()

    while IFS= read -r LINE; do
        [[ -z "$LINE" || "$LINE" == \#* ]] && continue
        i=$((i + 1))
        LINES+=("$LINE")
        IFS=: read -r SH SP ST <<< "$LINE"
        ST=$(echo "$ST" | xargs)
        echo -e "  ${GREEN}${i})${RESET} ${SH}:${SP} ${DIM}[${ST}]${RESET}"
    done < "$FILE"

    if [ $i -eq 0 ]; then
        echo -e "  ${DIM}No servers to remove.${RESET}"
        echo ""; read -rsp "  Press Enter to go back..."; return
    fi

    echo ""
    echo -ne "  ${WHITE}Number to remove${RESET} (0 = cancel): "
    read -r NUM

    if [[ "$NUM" =~ ^[0-9]+$ ]] && [ "$NUM" -ge 1 ] && [ "$NUM" -le $i ]; then
        local TARGET="${LINES[$((NUM - 1))]}"
        IFS=: read -r SH SP ST <<< "$TARGET"

        echo -ne "  ${RED}Remove ${SH}:${SP}?${RESET} (y/N): "
        read -r CONFIRM

        if [[ "$CONFIRM" =~ ^[yY]$ ]]; then
            grep -vF "$TARGET" "$FILE" > "${FILE}.tmp" && mv "${FILE}.tmp" "$FILE"
            echo -e "  ${GREEN}✔ Removed${RESET}"; sleep 1
        fi
    fi
}

# ============================================================
#  4) QUICK CHECK
# ============================================================
quick_check() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}  ── Quick check ──${RESET}"
    echo ""

    echo -ne "  ${WHITE}URL or IP${RESET}: "
    read -r HOST
    HOST=$(echo "$HOST" | sed 's|https\?://||' | sed 's|/.*||')

    if [ -z "$HOST" ]; then
        echo -e "\n  ${RED}✗ Empty${RESET}"; sleep 1; return
    fi

    echo -ne "  ${WHITE}Port${RESET} [443]: "
    read -r PORT; PORT=${PORT:-443}

    echo ""
    echo -ne "  ${DIM}Connecting to ${HOST}:${PORT}...${RESET} "

    CERT_DATA=$(echo | timeout 10 openssl s_client -servername "$HOST" \
        -connect "$HOST:$PORT" 2>/dev/null)

    if [ -z "$CERT_DATA" ]; then
        echo -e "${RED}✗ Could not connect${RESET}"
        echo ""; read -rsp "  Press Enter to go back..."; return
    fi

    SUBJECT=$(echo "$CERT_DATA" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
    ISSUER=$(echo "$CERT_DATA" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
    START=$(echo "$CERT_DATA" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
    END=$(echo "$CERT_DATA" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    SERIAL=$(echo "$CERT_DATA" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)
    SIG=$(echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | xargs)
    BITS=$(echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null | grep "Public-Key" | head -1 | xargs)

    DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))

    if [ "$DAYS" -le 0 ]; then COLOR="$RED"; TAG="✗ EXPIRED"
    elif [ "$DAYS" -le "$CRIT_DAYS" ]; then COLOR="$RED"; TAG="▲ ALERT"
    elif [ "$DAYS" -le "$WARN_DAYS" ]; then COLOR="$ORANGE"; TAG="● WARNING"
    else COLOR="$GREEN"; TAG="✔ OK"; fi

    echo -e "${GREEN}✔ Connected${RESET}"
    echo ""
    echo -e "  ${TL}$(repeat_char "$H" 70)${TR}"
    echo -e "  ${V} ${WHITE}${BOLD}Certificate for ${HOST}:${PORT}${RESET}$(printf "%*s" $((52 - ${#HOST} - ${#PORT})) "")${V}"
    echo -e "  ${LT}$(repeat_char "$H" 70)${RT}"
    echo -e "  ${V}  ${DIM}Subject:${RESET}     ${SUBJECT:0:55}$(printf "%*s" $((56 - ${#SUBJECT})) "")${V}"
    echo -e "  ${V}  ${DIM}Issuer:${RESET}      ${ISSUER:0:55}$(printf "%*s" $((56 - ${#ISSUER})) "")${V}"
    echo -e "  ${V}  ${DIM}Valid from:${RESET}   ${START}$(printf "%*s" $((52 - ${#START})) "")${V}"
    echo -e "  ${V}  ${DIM}Expires:${RESET}     ${END}$(printf "%*s" $((52 - ${#END})) "")${V}"
    echo -e "  ${V}  ${DIM}Days left:${RESET}   ${COLOR}${BOLD}${DAYS} days  [${TAG}]${RESET}$(printf "%*s" $((42 - ${#DAYS} - ${#TAG})) "")${V}"
    echo -e "  ${V}  ${DIM}Serial:${RESET}      ${SERIAL:0:55}$(printf "%*s" $((56 - ${#SERIAL})) "")${V}"
    echo -e "  ${V}  ${DIM}Algorithm:${RESET}   ${SIG:0:55}$(printf "%*s" $((56 - ${#SIG})) "")${V}"
    echo -e "  ${V}  ${DIM}Key:${RESET}         ${BITS:0:55}$(printf "%*s" $((56 - ${#BITS})) "")${V}"
    echo -e "  ${BL}$(repeat_char "$H" 70)${BR}"

    echo ""
    echo -ne "  Add to inventory? (y/N): "
    read -r SAVE

    if [[ "$SAVE" =~ ^[yY]$ ]]; then
        echo ""
        echo -e "  ${GREEN}1)${RESET}IIS  ${GREEN}2)${RESET}Apache  ${GREEN}3)${RESET}Nginx  ${GREEN}4)${RESET}Tomcat  ${GREEN}5)${RESET}Appliance  ${GREEN}6)${RESET}Proxy  ${GREEN}7)${RESET}Other"
        echo -ne "  ${CYAN}▸${RESET} "
        read -r TC
        case "$TC" in
            1) T="IIS" ;; 2) T="APACHE" ;; 3) T="NGINX" ;; 4) T="TOMCAT" ;;
            5) T="APPLIANCE" ;; 6) T="PROXY" ;;
            7) echo -ne "  Type: "; read -r T; T=$(echo "$T" | tr '[:lower:]' '[:upper:]' | xargs) ;;
            *) T="OTHER" ;;
        esac

        if grep -q "^${HOST}:${PORT}:" "$FILE" 2>/dev/null; then
            echo -e "  ${ORANGE}⚠ Already exists${RESET}"
        else
            echo "${HOST}:${PORT}:${T}" >> "$FILE"
            echo -e "  ${GREEN}✔ Saved: ${HOST}:${PORT} [${T}]${RESET}"
        fi
    fi

    echo ""
    read -rsp "  Press Enter to go back to dashboard..."
}

# ============================================================
#  6) EXPORT REPORT
# ============================================================
export_report() {
    REPORT="${SCRIPT_DIR}/report_$(date '+%Y%m%d_%H%M%S').txt"

    echo ""
    echo -ne "  ${DIM}Generating report...${RESET}"

    {
        echo "============================================="
        echo " CERTIFICATE REPORT - $(date '+%Y-%m-%d %H:%M')"
        echo " Host: $(hostname)"
        echo "============================================="
        echo ""

        # Remote
        TYPES=$(grep -v '^#' "$FILE" | grep -v '^$' | cut -d: -f3 | sort -u | xargs)

        if [ -n "$TYPES" ]; then
            echo "=== REMOTE SERVERS ==="
            echo ""
            for T in $TYPES; do
                echo "--- $T ---"
                grep -v '^#' "$FILE" | grep -v '^$' | while IFS=: read -r HOST PORT TYPE; do
                    TYPE=$(echo "$TYPE" | xargs)
                    [ "$TYPE" != "$T" ] && continue
                    PORT=${PORT:-443}
                    EXPIRY=$(echo | timeout 5 openssl s_client -servername "$HOST" \
                        -connect "$HOST:$PORT" 2>/dev/null \
                        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
                    if [ -z "$EXPIRY" ]; then
                        echo "[ERROR]    $HOST:$PORT - Could not connect"
                    else
                        DAYS=$(( ( $(date -d "$EXPIRY" +%s) - $(date +%s) ) / 86400 ))
                        if [ "$DAYS" -le 0 ]; then S="EXPIRED"
                        elif [ "$DAYS" -le 15 ]; then S="ALERT"
                        elif [ "$DAYS" -le 30 ]; then S="WARNING"
                        else S="OK"; fi
                        printf "[%-8s] %-45s | Days: %-5s | %s\n" "$S" "$HOST:$PORT" "$DAYS" "$EXPIRY"
                    fi
                done
                echo ""
            done
        fi

        # Local
        CERT_FILES=$(find "$CERT_STORE" -maxdepth 1 -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der" \) 2>/dev/null | sort)
        if [ -n "$CERT_FILES" ]; then
            echo "=== LOCAL CERTIFICATES ==="
            echo "Store: ${CERT_STORE}/"
            echo ""
            while IFS= read -r CF; do
                [ -z "$CF" ] && continue
                FNAME=$(basename "$CF")
                END=$(openssl x509 -in "$CF" -noout -enddate 2>/dev/null | cut -d= -f2)
                [ -z "$END" ] && END=$(openssl x509 -in "$CF" -inform DER -noout -enddate 2>/dev/null | cut -d= -f2)
                if [ -z "$END" ]; then
                    echo "[ERROR]    $FNAME - Could not read"
                else
                    DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
                    if [ "$DAYS" -le 0 ]; then S="EXPIRED"
                    elif [ "$DAYS" -le 15 ]; then S="ALERT"
                    elif [ "$DAYS" -le 30 ]; then S="WARNING"
                    else S="OK"; fi
                    printf "[%-8s] %-45s | Days: %-5s | %s\n" "$S" "$FNAME" "$DAYS" "$END"
                fi
            done <<< "$CERT_FILES"
            echo ""
        fi
    } > "$REPORT"

    echo -e " ${GREEN}✔${RESET}"
    echo -e "\n  ${GREEN}Saved: ${WHITE}${REPORT}${RESET}"
    sleep 2
}

# ============================================================
#  8) IMPORT CERTIFICATE
# ============================================================
import_certificate() {
    clear
    echo ""
    echo -e "${MAGENTA}${BOLD}  ── Import certificate to local store ──${RESET}"
    echo -e "  ${DIM}Store: ${CERT_STORE}/${RESET}"
    echo -e "  ${DIM}Supported: .pem .crt .cer .der .pfx .p12${RESET}"
    echo ""
    echo -e "  ${WHITE}${BOLD}Import method:${RESET}"
    echo ""
    echo -e "  ${GREEN}1)${RESET} Local path          ${DIM}(copy from a path on this machine)${RESET}"
    echo -e "  ${GREEN}2)${RESET} Network share        ${DIM}(mount CIFS/SMB or NFS, then import)${RESET}"
    echo -e "  ${GREEN}3)${RESET} Download from URL    ${DIM}(curl / wget)${RESET}"
    echo -e "  ${GREEN}4)${RESET} Paste PEM content    ${DIM}(paste base64 certificate from clipboard)${RESET}"
    echo -e "  ${GREEN}0)${RESET} Back"
    echo ""
    echo -ne "  ${CYAN}▸${RESET} "
    read -r METHOD

    case "$METHOD" in
        1) import_from_path ;;
        2) import_from_network ;;
        3) import_from_url ;;
        4) import_from_paste ;;
        0|*) return ;;
    esac

    echo ""
    read -rsp "  Press Enter to go back to dashboard..."
}

# --- 8.1) Import from local path ---
import_from_path() {
    echo ""
    echo -ne "  ${WHITE}Full path to certificate file${RESET}: "
    read -r CERT_PATH

    if [ ! -f "$CERT_PATH" ]; then
        echo -e "  ${RED}✗ File not found: ${CERT_PATH}${RESET}"
        return
    fi

    import_cert_file "$CERT_PATH"
}

# --- 8.2) Import from network share ---
import_from_network() {
    echo ""
    echo -e "  ${WHITE}${BOLD}Share type:${RESET}"
    echo ""
    echo -e "  ${GREEN}1)${RESET} CIFS/SMB  ${DIM}(Windows share: //server/share)${RESET}"
    echo -e "  ${GREEN}2)${RESET} NFS       ${DIM}(NFS export: server:/export/path)${RESET}"
    echo ""
    echo -ne "  ${CYAN}▸${RESET} "
    read -r SHARE_TYPE

    case "$SHARE_TYPE" in
        1) import_from_cifs ;;
        2) import_from_nfs ;;
        *) return ;;
    esac
}

import_from_cifs() {
    echo ""
    echo -ne "  ${WHITE}UNC path${RESET} (e.g. //fileserver/certs): "
    read -r UNC_PATH

    if [ -z "$UNC_PATH" ]; then
        echo -e "  ${RED}✗ Empty path${RESET}"; return
    fi

    echo -ne "  ${WHITE}Domain${RESET} (leave empty if none): "
    read -r DOMAIN

    echo -ne "  ${WHITE}Username${RESET}: "
    read -r SMB_USER

    echo -ne "  ${WHITE}Password${RESET}: "
    read -rs SMB_PASS
    echo ""

    # Build mount options
    local MOUNT_OPTS="username=${SMB_USER},password=${SMB_PASS}"
    [ -n "$DOMAIN" ] && MOUNT_OPTS="${MOUNT_OPTS},domain=${DOMAIN}"

    # Check cifs-utils
    if ! command -v mount.cifs &>/dev/null; then
        echo -e "  ${RED}✗ cifs-utils not installed. Run: apt install cifs-utils${RESET}"
        return
    fi

    echo -ne "  ${DIM}Mounting ${UNC_PATH}...${RESET} "

    # Unmount if already mounted
    mountpoint -q "$MOUNT_DIR" 2>/dev/null && umount "$MOUNT_DIR" 2>/dev/null

    if mount -t cifs "$UNC_PATH" "$MOUNT_DIR" -o "$MOUNT_OPTS,ro" 2>/dev/null; then
        echo -e "${GREEN}✔ Mounted${RESET}"
    else
        echo -e "${RED}✗ Mount failed${RESET}"
        echo -e "  ${DIM}Check path, credentials, and that cifs-utils is installed.${RESET}"
        return
    fi

    # List certificate files
    echo ""
    echo -e "  ${WHITE}${BOLD}Certificates found:${RESET}"
    echo ""

    local j=0
    declare -a FOUND_FILES=()

    while IFS= read -r F; do
        [ -z "$F" ] && continue
        j=$((j + 1))
        FOUND_FILES+=("$F")
        echo -e "  ${GREEN}${j})${RESET} $(basename "$F")"
    done < <(find "$MOUNT_DIR" -maxdepth 3 -type f \( \
        -iname "*.pem" -o -iname "*.crt" -o -iname "*.cer" \
        -o -iname "*.der" -o -iname "*.pfx" -o -iname "*.p12" \) 2>/dev/null | sort)

    if [ $j -eq 0 ]; then
        echo -e "  ${DIM}No certificate files found in the share.${RESET}"
        umount "$MOUNT_DIR" 2>/dev/null
        return
    fi

    echo -e "  ${GREEN}A)${RESET} Import ALL"
    echo ""
    echo -ne "  ${WHITE}Select file number${RESET} (A = all, 0 = cancel): "
    read -r SELECTION

    if [[ "$SELECTION" =~ ^[aA]$ ]]; then
        for F in "${FOUND_FILES[@]}"; do
            echo -e "\n  ${DIM}── $(basename "$F") ──${RESET}"
            import_cert_file "$F"
        done
    elif [[ "$SELECTION" =~ ^[0-9]+$ ]] && [ "$SELECTION" -ge 1 ] && [ "$SELECTION" -le $j ]; then
        import_cert_file "${FOUND_FILES[$((SELECTION - 1))]}"
    fi

    echo ""
    echo -ne "  ${DIM}Unmounting share...${RESET} "
    umount "$MOUNT_DIR" 2>/dev/null
    echo -e "${GREEN}✔${RESET}"
}

import_from_nfs() {
    echo ""
    echo -ne "  ${WHITE}NFS export${RESET} (e.g. nfs-server:/export/certs): "
    read -r NFS_PATH

    if [ -z "$NFS_PATH" ]; then
        echo -e "  ${RED}✗ Empty path${RESET}"; return
    fi

    # Check nfs-common
    if ! command -v mount.nfs &>/dev/null; then
        echo -e "  ${RED}✗ nfs-common not installed. Run: apt install nfs-common${RESET}"
        return
    fi

    echo -ne "  ${DIM}Mounting ${NFS_PATH}...${RESET} "

    mountpoint -q "$MOUNT_DIR" 2>/dev/null && umount "$MOUNT_DIR" 2>/dev/null

    if mount -t nfs "$NFS_PATH" "$MOUNT_DIR" -o ro,nolock 2>/dev/null; then
        echo -e "${GREEN}✔ Mounted${RESET}"
    else
        echo -e "${RED}✗ Mount failed${RESET}"
        echo -e "  ${DIM}Check export path and that nfs-common is installed.${RESET}"
        return
    fi

    # List certificate files
    echo ""
    echo -e "  ${WHITE}${BOLD}Certificates found:${RESET}"
    echo ""

    local j=0
    declare -a FOUND_FILES=()

    while IFS= read -r F; do
        [ -z "$F" ] && continue
        j=$((j + 1))
        FOUND_FILES+=("$F")
        echo -e "  ${GREEN}${j})${RESET} $(basename "$F")"
    done < <(find "$MOUNT_DIR" -maxdepth 3 -type f \( \
        -iname "*.pem" -o -iname "*.crt" -o -iname "*.cer" \
        -o -iname "*.der" -o -iname "*.pfx" -o -iname "*.p12" \) 2>/dev/null | sort)

    if [ $j -eq 0 ]; then
        echo -e "  ${DIM}No certificate files found in the share.${RESET}"
        umount "$MOUNT_DIR" 2>/dev/null
        return
    fi

    echo -e "  ${GREEN}A)${RESET} Import ALL"
    echo ""
    echo -ne "  ${WHITE}Select file number${RESET} (A = all, 0 = cancel): "
    read -r SELECTION

    if [[ "$SELECTION" =~ ^[aA]$ ]]; then
        for F in "${FOUND_FILES[@]}"; do
            echo -e "\n  ${DIM}── $(basename "$F") ──${RESET}"
            import_cert_file "$F"
        done
    elif [[ "$SELECTION" =~ ^[0-9]+$ ]] && [ "$SELECTION" -ge 1 ] && [ "$SELECTION" -le $j ]; then
        import_cert_file "${FOUND_FILES[$((SELECTION - 1))]}"
    fi

    echo ""
    echo -ne "  ${DIM}Unmounting share...${RESET} "
    umount "$MOUNT_DIR" 2>/dev/null
    echo -e "${GREEN}✔${RESET}"
}

# --- 8.3) Import from URL ---
import_from_url() {
    echo ""
    echo -ne "  ${WHITE}Certificate URL${RESET}: "
    read -r CERT_URL

    if [ -z "$CERT_URL" ]; then
        echo -e "  ${RED}✗ Empty URL${RESET}"; return
    fi

    local FNAME
    FNAME=$(basename "$CERT_URL" | sed 's/[?#].*//')
    [ -z "$FNAME" ] && FNAME="downloaded_cert.pem"

    local TMP_FILE="/tmp/cert_download_$$_${FNAME}"

    echo -ne "  ${DIM}Downloading...${RESET} "

    local DL_OK=0
    if command -v curl &>/dev/null; then
        if curl -fsSL -o "$TMP_FILE" --connect-timeout 10 "$CERT_URL" 2>/dev/null; then
            DL_OK=1
        fi
    elif command -v wget &>/dev/null; then
        if wget -q -O "$TMP_FILE" --timeout=10 "$CERT_URL" 2>/dev/null; then
            DL_OK=1
        fi
    else
        echo -e "${RED}✗ Neither curl nor wget found${RESET}"
        return
    fi

    if [ $DL_OK -eq 0 ]; then
        echo -e "${RED}✗ Download failed${RESET}"
        rm -f "$TMP_FILE"
        return
    fi

    echo -e "${GREEN}✔${RESET}"
    import_cert_file "$TMP_FILE"
    rm -f "$TMP_FILE"
}

# --- 8.4) Paste PEM content ---
import_from_paste() {
    echo ""
    echo -ne "  ${WHITE}Certificate name${RESET} (e.g. wildcard_domain_com): "
    read -r CERT_NAME

    if [ -z "$CERT_NAME" ]; then
        echo -e "  ${RED}✗ Empty name${RESET}"; return
    fi

    CERT_NAME=$(echo "$CERT_NAME" | tr ' ' '_' | sed 's/[^a-zA-Z0-9._-]//g')

    echo ""
    echo -e "  ${DIM}Paste the PEM certificate below (including BEGIN/END lines).${RESET}"
    echo -e "  ${DIM}When done, type ${WHITE}END${DIM} on a new line and press Enter.${RESET}"
    echo ""

    local TMP_FILE="/tmp/cert_paste_$$_${CERT_NAME}.pem"
    > "$TMP_FILE"

    while IFS= read -r LINE; do
        [ "$LINE" = "END" ] && break
        echo "$LINE" >> "$TMP_FILE"
    done

    if ! grep -q "BEGIN CERTIFICATE" "$TMP_FILE" 2>/dev/null; then
        echo -e "  ${RED}✗ No valid PEM header found${RESET}"
        rm -f "$TMP_FILE"
        return
    fi

    import_cert_file "$TMP_FILE"
    rm -f "$TMP_FILE"
}

# ============================================================
#  9) REMOVE LOCAL CERTIFICATE
# ============================================================
delete_certificate() {
    clear
    echo ""
    echo -e "${MAGENTA}${BOLD}  ── Remove local certificate ──${RESET}"
    echo -e "  ${DIM}Store: ${CERT_STORE}/${RESET}"
    echo ""

    local j=0
    declare -a CERT_LIST=()

    while IFS= read -r CF; do
        [ -z "$CF" ] && continue
        j=$((j + 1))
        CERT_LIST+=("$CF")

        # Show basic info alongside filename
        local END DAYS TAG_C TAG_T
        END=$(openssl x509 -in "$CF" -noout -enddate 2>/dev/null | cut -d= -f2)
        [ -z "$END" ] && END=$(openssl x509 -in "$CF" -inform DER -noout -enddate 2>/dev/null | cut -d= -f2)

        if [ -n "$END" ]; then
            DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
            if [ "$DAYS" -le 0 ]; then TAG_C="$RED"; TAG_T="EXPIRED"
            elif [ "$DAYS" -le "$CRIT_DAYS" ]; then TAG_C="$RED"; TAG_T="ALERT"
            elif [ "$DAYS" -le "$WARN_DAYS" ]; then TAG_C="$ORANGE"; TAG_T="WARNING"
            else TAG_C="$GREEN"; TAG_T="OK"; fi
            echo -e "  ${GREEN}${j})${RESET} $(basename "$CF")  ${TAG_C}[${TAG_T} - ${DAYS}d]${RESET}"
        else
            echo -e "  ${GREEN}${j})${RESET} $(basename "$CF")  ${RED}[UNREADABLE]${RESET}"
        fi

    done < <(find "$CERT_STORE" -maxdepth 1 -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der" \) 2>/dev/null | sort)

    if [ $j -eq 0 ]; then
        echo -e "  ${DIM}No local certificates to remove.${RESET}"
        echo ""; read -rsp "  Press Enter to go back..."; return
    fi

    echo ""
    echo -ne "  ${WHITE}Number to remove${RESET} (0 = cancel): "
    read -r NUM

    if [[ "$NUM" =~ ^[0-9]+$ ]] && [ "$NUM" -ge 1 ] && [ "$NUM" -le $j ]; then
        local TARGET="${CERT_LIST[$((NUM - 1))]}"
        local TNAME
        TNAME=$(basename "$TARGET")

        echo -ne "  ${RED}Remove ${TNAME}?${RESET} (y/N): "
        read -r CONFIRM

        if [[ "$CONFIRM" =~ ^[yY]$ ]]; then
            rm -f "$TARGET"
            echo -e "  ${GREEN}✔ Removed: ${TNAME}${RESET}"
            sleep 1
        fi
    fi
}

# ============================================================
#  MAIN LOOP: Dashboard + Menu + Auto-refresh
# ============================================================
while true; do
    draw_dashboard
    draw_menu

    if [ "$REFRESH" -gt 0 ]; then
        read -t "$REFRESH" -r OPTION
        READ_EXIT=$?
        if [ $READ_EXIT -gt 128 ]; then
            continue
        fi
    else
        read -r OPTION
    fi

    case "$OPTION" in
        1) add_server ;;
        2) list_servers ;;
        3) delete_server ;;
        4) quick_check ;;
        5) ;; # refresh
        6) export_report ;;
        7) change_refresh ;;
        8) import_certificate ;;
        9) delete_certificate ;;
        0) clear; echo -e "\n  ${DIM}Goodbye 👋${RESET}\n"; exit 0 ;;
        *) ;;
    esac
done
