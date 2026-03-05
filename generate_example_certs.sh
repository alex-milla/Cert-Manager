#!/bin/bash
# ============================================================
#  generate_example_certs.sh
#  Author: Alex Millà - alexmilla.dev
#  Creates example certificates in all supported formats
#  to test cert_manager.sh
#
#  Usage: sudo ./generate_example_certs.sh [output_dir]
#  Default output: /opt/cert-monitor/example-certs/
# ============================================================

# --- Colors ---
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
ORANGE='\033[1;33m'
WHITE='\033[1;37m'
DIM='\033[0;37m'
BOLD='\033[1m'
RESET='\033[0m'

# --- Output directory ---
OUT_DIR="${1:-/opt/cert-monitor/example-certs}"

echo ""
echo -e "${CYAN}${BOLD}  ╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}  ║     Example Certificate Generator for CertManager   ║${RESET}"
echo -e "${CYAN}${BOLD}  ╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# --- Check OpenSSL ---
if ! command -v openssl &>/dev/null; then
    echo -e "  ${RED}✗ OpenSSL not found. Install it: apt install openssl${RESET}"
    exit 1
fi

OPENSSL_VER=$(openssl version | cut -d' ' -f2)
OPENSSL_MAJOR=$(echo "$OPENSSL_VER" | cut -d. -f1)
echo -e "  ${DIM}OpenSSL: ${OPENSSL_VER}${RESET}"
echo -e "  ${DIM}Output:  ${OUT_DIR}/${RESET}"
echo ""

# --- Create output directory ---
mkdir -p "$OUT_DIR"
cd "$OUT_DIR" || exit 1

# --- Helper: check if faketime is available (needed for expired cert on OpenSSL 1.x) ---
HAS_FAKETIME=0
if command -v faketime &>/dev/null; then
    HAS_FAKETIME=1
fi

# ============================================================
#  1) PEM — Wildcard, 365 days → OK
# ============================================================
echo -ne "  ${WHITE}[1/6]${RESET} Wildcard PEM (365d - OK)............ "

openssl req -x509 -newkey rsa:2048 \
    -keyout wildcard_acme_corp.key \
    -out wildcard_acme_corp.pem \
    -days 365 -nodes \
    -subj "/C=ES/ST=Barcelona/O=ACME Corp/CN=*.acme-corp.com" \
    -addext "subjectAltName=DNS:*.acme-corp.com,DNS:acme-corp.com" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✔${RESET}  ${DIM}wildcard_acme_corp.pem${RESET}"
else
    echo -e "${RED}✗ FAILED${RESET}"
fi

# ============================================================
#  2) CRT — Intranet, 25 days → WARNING
# ============================================================
echo -ne "  ${WHITE}[2/6]${RESET} Intranet CRT (25d - WARNING)....... "

openssl req -x509 -newkey rsa:2048 \
    -keyout webserver_intranet.key \
    -out webserver_intranet.crt \
    -days 25 -nodes \
    -subj "/C=ES/ST=Madrid/O=Intranet Services/CN=intranet.local" \
    -addext "subjectAltName=DNS:intranet.local,DNS:www.intranet.local" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✔${RESET}  ${DIM}webserver_intranet.crt${RESET}"
else
    echo -e "${RED}✗ FAILED${RESET}"
fi

# ============================================================
#  3) CER — Exchange, 10 days → ALERT
# ============================================================
echo -ne "  ${WHITE}[3/6]${RESET} Exchange CER (10d - ALERT)......... "

openssl req -x509 -newkey rsa:4096 \
    -keyout exchange_mail.key \
    -out exchange_mail.cer \
    -days 10 -nodes \
    -subj "/C=US/ST=New York/O=FinBank Inc/CN=mail.finbank.com" \
    -addext "subjectAltName=DNS:mail.finbank.com,DNS:autodiscover.finbank.com" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✔${RESET}  ${DIM}exchange_mail.cer${RESET}"
else
    echo -e "${RED}✗ FAILED${RESET}"
fi

# ============================================================
#  4) DER — Appliance, 200 days → OK (binary format)
# ============================================================
echo -ne "  ${WHITE}[4/6]${RESET} Appliance DER (200d - OK).......... "

openssl req -x509 -newkey rsa:2048 \
    -keyout appliance_fw.key \
    -out appliance_fw_tmp.pem \
    -days 200 -nodes \
    -subj "/C=DE/ST=Berlin/O=SecureNet GmbH/CN=fw01.securenet.de" 2>/dev/null \
&& openssl x509 -in appliance_fw_tmp.pem -outform DER -out appliance_fw.der 2>/dev/null

if [ $? -eq 0 ]; then
    rm -f appliance_fw_tmp.pem
    echo -e "${GREEN}✔${RESET}  ${DIM}appliance_fw.der${RESET}"
else
    echo -e "${RED}✗ FAILED${RESET}"
fi

# ============================================================
#  5) PFX — IIS Portal, 5 days → ALERT (password: Test1234)
# ============================================================
echo -ne "  ${WHITE}[5/6]${RESET} IIS PFX (5d - ALERT, pw:Test1234). "

openssl req -x509 -newkey rsa:2048 \
    -keyout iis_portal.key \
    -out iis_portal_tmp.pem \
    -days 5 -nodes \
    -subj "/C=ES/ST=Barcelona/O=Portal Corp/CN=portal.corp.local" \
    -addext "subjectAltName=DNS:portal.corp.local,DNS:portal" 2>/dev/null \
&& openssl pkcs12 -export \
    -out iis_portal.pfx \
    -inkey iis_portal.key \
    -in iis_portal_tmp.pem \
    -passout pass:Test1234 2>/dev/null

if [ $? -eq 0 ]; then
    rm -f iis_portal_tmp.pem
    echo -e "${GREEN}✔${RESET}  ${DIM}iis_portal.pfx${RESET}"
else
    echo -e "${RED}✗ FAILED${RESET}"
fi

# ============================================================
#  6) PEM — Expired (2 days ago)
#     OpenSSL 3.x: uses -not_before / -not_after
#     OpenSSL 1.x: uses faketime fallback
# ============================================================
echo -ne "  ${WHITE}[6/6]${RESET} Expired PEM (-2d - EXPIRED)........ "

EXPIRED_OK=0

if [ "$OPENSSL_MAJOR" -ge 3 ]; then
    # OpenSSL 3.x — native date control
    openssl req -x509 -newkey rsa:2048 \
        -keyout expired_legacy.key \
        -out expired_legacy.pem \
        -nodes \
        -subj "/C=ES/ST=Valencia/O=Legacy Systems/CN=old.legacy.internal" \
        -not_before "$(date -d '-30 days' -u +%Y%m%d%H%M%SZ)" \
        -not_after "$(date -d '-2 days' -u +%Y%m%d%H%M%SZ)" 2>/dev/null
    [ $? -eq 0 ] && EXPIRED_OK=1
elif [ $HAS_FAKETIME -eq 1 ]; then
    # OpenSSL 1.x — faketime fallback
    faketime '-30 days' openssl req -x509 -newkey rsa:2048 \
        -keyout expired_legacy.key \
        -out expired_legacy.pem \
        -days 28 -nodes \
        -subj "/C=ES/ST=Valencia/O=Legacy Systems/CN=old.legacy.internal" 2>/dev/null
    [ $? -eq 0 ] && EXPIRED_OK=1
fi

if [ $EXPIRED_OK -eq 1 ]; then
    echo -e "${GREEN}✔${RESET}  ${DIM}expired_legacy.pem${RESET}"
else
    echo -e "${ORANGE}⚠ SKIPPED${RESET}"
    if [ "$OPENSSL_MAJOR" -lt 3 ] && [ $HAS_FAKETIME -eq 0 ]; then
        echo -e "       ${DIM}OpenSSL < 3.x and faketime not found.${RESET}"
        echo -e "       ${DIM}Install it: apt install faketime${RESET}"
    fi
fi

# ============================================================
#  Cleanup: remove private keys
# ============================================================
rm -f "$OUT_DIR"/*.key "$OUT_DIR"/*.csr 2>/dev/null

# ============================================================
#  Verification table
# ============================================================
echo ""
echo -e "  ${WHITE}${BOLD}── Verification ──${RESET}"
echo ""
printf "  ${DIM}%-30s  %6s  %-8s  %s${RESET}\n" "FILE" "DAYS" "STATUS" "EXPIRATION"
echo -e "  ${DIM}$(printf '%0.s─' $(seq 1 85))${RESET}"

for f in "$OUT_DIR"/*.pem "$OUT_DIR"/*.crt "$OUT_DIR"/*.cer; do
    [ ! -f "$f" ] && continue
    FNAME=$(basename "$f")
    END=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -n "$END" ]; then
        DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
        if [ "$DAYS" -le 0 ]; then       C="$RED"; S="EXPIRED"
        elif [ "$DAYS" -le 15 ]; then     C="$RED"; S="ALERT"
        elif [ "$DAYS" -le 30 ]; then     C="$ORANGE"; S="WARNING"
        else                              C="$GREEN"; S="OK"
        fi
        printf "  %-30s  ${C}%6d  %-8s${RESET}  ${DIM}%s${RESET}\n" "$FNAME" "$DAYS" "$S" "$END"
    fi
done

# DER
if [ -f "$OUT_DIR/appliance_fw.der" ]; then
    END=$(openssl x509 -in "$OUT_DIR/appliance_fw.der" -inform DER -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -n "$END" ]; then
        DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
        printf "  %-30s  ${GREEN}%6d  %-8s${RESET}  ${DIM}%s${RESET}\n" "appliance_fw.der" "$DAYS" "OK" "$END"
    fi
fi

# PFX
if [ -f "$OUT_DIR/iis_portal.pfx" ]; then
    END=$(openssl pkcs12 -in "$OUT_DIR/iis_portal.pfx" -clcerts -nokeys -passin pass:Test1234 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -n "$END" ]; then
        DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))
        C="$RED"; S="ALERT"
        printf "  %-30s  ${C}%6d  %-8s${RESET}  ${DIM}%s (pw:Test1234)${RESET}\n" "iis_portal.pfx" "$DAYS" "$S" "$END"
    fi
fi

# ============================================================
#  Summary
# ============================================================
TOTAL=$(find "$OUT_DIR" -maxdepth 1 -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der" -o -name "*.pfx" \) | wc -l)

echo ""
echo -e "  ${GREEN}${BOLD}✔ Done!${RESET} ${DIM}${TOTAL} certificates in ${OUT_DIR}/${RESET}"
echo ""
echo -e "  ${WHITE}${BOLD}To import into cert_manager:${RESET}"
echo ""
echo -e "  ${DIM}# Copy all (except PFX) directly to the store:${RESET}"
echo -e "  cp ${OUT_DIR}/*.pem ${OUT_DIR}/*.crt ${OUT_DIR}/*.cer ${OUT_DIR}/*.der /opt/cert-monitor/certs/"
echo ""
echo -e "  ${DIM}# Import PFX via script menu (option 8 → 1):${RESET}"
echo -e "  ${DIM}# Path: ${OUT_DIR}/iis_portal.pfx | Password: Test1234${RESET}"
echo ""
