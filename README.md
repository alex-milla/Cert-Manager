# 🔒 Certificate Manager

[![License: CertManager Community](https://img.shields.io/badge/License-Community-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-1.1.1%2B-orange.svg)](https://www.openssl.org/)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support-yellow?logo=buymeacoffee)](https://buymeacoffee.com/alexmilla)

**A terminal-based SSL/TLS certificate monitoring tool with an interactive dashboard, local certificate store, and configurable auto-refresh.**

Monitor remote server certificates and local certificate files from a single, color-coded terminal interface. Detect expiring or expired certificates before they cause outages.

```
  ╔════════════════════════════════════════════════════════════════════════════════════════════════╗
  ║                              🔒  CERTIFICATE MONITOR v1.3  🔒                                ║
  ║                              2026-03-05 14:30:00                                              ║
  ╚════════════════════════════════════════════════════════════════════════════════════════════════╝

  SUMMARY  (thresholds: warning ≤30d | alert ≤15d)

  ┌ ✔ OK: 3 ┐  ┌ ● WARN: 1 ┐  ┌ ✗ ALERT: 2 ┐  ✗ ERROR: 0  │ Total: 6

  🪶  APACHE ─────────────────────────────────────────────────────────────────────────────
  ┌─────────────┬──────────────────────────────────────────────┬───────────┬─────────────────────────────┐
  │ STATUS      │ NAME                                         │ DAYS      │ EXPIRATION DATE             │
  ├─────────────┼──────────────────────────────────────────────┼───────────┼─────────────────────────────┤
  │ ✔ OK        │ web01.domain.com:443                         │ 185       │ Sep 04 23:59:59 2026 GMT    │
  │ ▲ ALERT     │ web02.domain.com:443                         │ 8         │ Mar 13 23:59:59 2026 GMT    │
  └─────────────┴──────────────────────────────────────────────┴───────────┴─────────────────────────────┘

  📁  LOCAL CERTIFICATES ─────────────────────────────────────────────────────────────────
  Store: /opt/cert-monitor/certs/ (3 files)
  ┌─────────────┬──────────────────────────────────────────────┬───────────┬─────────────────────────────┐
  │ ✔ OK        │ wildcard_acme_corp.pem                       │ 364       │ Mar 05 22:15:00 2027 GMT    │
  │ ● WARNING   │ webserver_intranet.crt                       │ 24        │ Mar 30 22:15:00 2026 GMT    │
  │ ✗ EXPIRED   │ expired_legacy.pem                           │ -2        │ Mar 03 22:15:03 2026 GMT    │
  └─────────────┴──────────────────────────────────────────────┴───────────┴─────────────────────────────┘

  ────────────────────────────────────────────────────────────────────────────────────────────────────
  ⏱  Auto-refresh: every 5m │ Next: 14:35:00 │ Press any key at any time to interact

  SERVERS                                                CERT STORE
  1) Add server   2) Inventory   3) Remove server        8) Import certificate   9) Remove certificate

  TOOLS
  4) Quick check  5) Refresh     6) Export report        7) ⏱ Set interval       0) Exit

  ▸
```

---

## ✨ Features

- **Live dashboard** — Color-coded status for all certificates at a glance (OK / WARNING / ALERT / EXPIRED / ERROR)
- **Remote monitoring** — Check SSL/TLS certificates on any reachable server via OpenSSL `s_client`
- **Local certificate store** — Import and monitor certificate files (`.pem`, `.crt`, `.cer`, `.der`, `.pfx`, `.p12`)
- **Auto-refresh** — Configurable interval (30s to 24h) with `read -t` timeout; dashboard refreshes unattended
- **Multiple import methods** — Local path, CIFS/SMB share, NFS share, URL download (curl/wget), or paste PEM content
- **PFX/P12 support** — Extracts public certificate only (prompts password once, private key is never stored)
- **DER auto-conversion** — Binary DER certificates are automatically converted to PEM on import
- **Server grouping** — Servers categorized by type (IIS, Apache, Nginx, Tomcat, Appliance, Proxy) with icons
- **Quick check** — One-off certificate inspection without saving (shows subject, issuer, dates, serial, algorithm, key size)
- **Export report** — Generate a plain-text report file with timestamp for documentation or auditing
- **Persistent settings** — Refresh interval is saved between executions

---

## 📋 Requirements

- **OS**: Linux (Ubuntu/Debian, RHEL/CentOS, or any distro with bash 4+)
- **OpenSSL**: 1.1.1+ (OpenSSL 3.x recommended for full functionality)
- **Bash**: 4.0+ (uses associative arrays)
- **Optional**:
  - `cifs-utils` — For CIFS/SMB network share imports
  - `nfs-common` — For NFS network share imports
  - `curl` or `wget` — For URL-based certificate downloads
  - `faketime` — For generating expired test certificates on OpenSSL < 3.x

---

## 🚀 Installation

### Quick install

```bash
# Clone the repository
git clone https://github.com/alex-milla/cert-monitor.git

# Copy to the recommended path
sudo cp -r cert-monitor /opt/cert-monitor

# Set permissions
sudo chmod +x /opt/cert-monitor/cert_manager.sh
sudo chmod +x /opt/cert-monitor/generate_example_certs.sh

# Run
/opt/cert-monitor/cert_manager.sh
```

### Manual install

```bash
# 1. Ensure OpenSSL is installed
sudo apt update && sudo apt install -y openssl

# 2. Create the directory structure
sudo mkdir -p /opt/cert-monitor/certs

# 3. Copy the script
sudo cp cert_manager.sh /opt/cert-monitor/
sudo chmod +x /opt/cert-monitor/cert_manager.sh

# 4. (Optional) Install network share dependencies
sudo apt install -y cifs-utils   # For CIFS/SMB mounts
sudo apt install -y nfs-common   # For NFS mounts

# 5. Run
/opt/cert-monitor/cert_manager.sh
```

### Directory structure

```
/opt/cert-monitor/
├── cert_manager.sh              # Main script
├── generate_example_certs.sh    # Test certificate generator
├── servers.txt                  # Remote server inventory (auto-created)
├── certs/                       # Local certificate store (auto-created)
│   ├── wildcard_domain.pem
│   ├── exchange_cert.pem
│   └── ...
├── mnt/                         # Temporary mount point for network shares (auto-created)
└── .refresh_interval            # Saved refresh setting (auto-created)
```

---

## 📖 Usage

### Starting the tool

```bash
# Default auto-refresh (every 5 minutes)
./cert_manager.sh

# Custom refresh interval (in seconds)
./cert_manager.sh --refresh 60      # Every minute
./cert_manager.sh --refresh 3600    # Every hour
./cert_manager.sh --refresh 86400   # Every 24 hours

# Manual refresh only (no auto-refresh)
./cert_manager.sh --refresh 0
```

### Menu options

| Key | Action | Description |
|-----|--------|-------------|
| `1` | **Add server** | Register a remote server (URL/IP, port, type) for monitoring |
| `2` | **Inventory** | List all registered remote servers and local certificates |
| `3` | **Remove server** | Delete a remote server from the inventory |
| `4` | **Quick check** | One-off certificate inspection without saving to inventory |
| `5` | **Refresh** | Manually refresh the dashboard |
| `6` | **Export report** | Generate a timestamped plain-text report file |
| `7` | **Set interval** | Change the auto-refresh timer (30s to 24h, custom, or disabled) |
| `8` | **Import certificate** | Import a certificate file into the local store |
| `9` | **Remove certificate** | Delete a certificate from the local store |
| `0` | **Exit** | Quit the tool |

---

## 🖥️ Remote Server Monitoring

### Adding a server

Select option `1` and follow the prompts:

```
  ── Add new server ──

  Server URL or IP (e.g. web01.domain.com): mail.company.com
  Port [443]: 443

  Web server type:

  1) IIS        2) Apache     3) Nginx
  4) Tomcat     5) Appliance  6) Proxy
  7) Other

  ▸ Type: 1

  Testing connection to mail.company.com:443... ✔ OK (expires in 185 days)
  ✔ Added: mail.company.com:443 [IIS]
```

The server inventory is stored in `servers.txt` using a simple format:

```
# host:port:type
mail.company.com:443:IIS
web01.domain.com:443:APACHE
proxy.internal:8443:PROXY
```

### Quick check

Option `4` lets you inspect any server's certificate without adding it to the inventory:

```
  ── Quick check ──

  URL or IP: github.com
  Port [443]: 443

  Connecting to github.com:443... ✔ Connected

  ┌──────────────────────────────────────────────────────────────────────┐
  │ Certificate for github.com:443                                      │
  ├──────────────────────────────────────────────────────────────────────┤
  │  Subject:     CN = github.com                                       │
  │  Issuer:      C = US, O = DigiCert Inc, CN = DigiCert SHA2 ...     │
  │  Valid from:  Mar 15 00:00:00 2024 GMT                              │
  │  Expires:     Mar 14 23:59:59 2025 GMT                              │
  │  Days left:   190 days  [✔ OK]                                      │
  │  Serial:      0A1B2C3D4E5F...                                       │
  │  Algorithm:   Signature Algorithm: sha256WithRSAEncryption          │
  │  Key:         Public-Key: (2048 bit)                                │
  └──────────────────────────────────────────────────────────────────────┘

  Add to inventory? (y/N):
```

---

## 📁 Local Certificate Store

### Importing certificates

Select option `8` to import certificates into the local store:

```
  ── Import certificate to local store ──
  Store: /opt/cert-monitor/certs/
  Supported: .pem .crt .cer .der .pfx .p12

  Import method:

  1) Local path          (copy from a path on this machine)
  2) Network share       (mount CIFS/SMB or NFS, then import)
  3) Download from URL   (curl / wget)
  4) Paste PEM content   (paste base64 certificate from clipboard)
  0) Back
```

### Import methods

#### 1) Local path

Copy a certificate from anywhere on the filesystem:

```
  Full path to certificate file: /tmp/wildcard.pem
  Validating certificate... ✔
  ✔ Imported: wildcard.pem
```

#### 2) Network share (CIFS/SMB)

Mount a Windows share, browse for certificates, and import:

```
  Share type:
  1) CIFS/SMB  (Windows share: //server/share)
  2) NFS       (NFS export: server:/export/path)

  ▸ 1

  UNC path (e.g. //fileserver/certs): //fs01/certificates
  Domain (leave empty if none): CORP
  Username: admin
  Password: ****

  Mounting //fs01/certificates... ✔ Mounted

  Certificates found:
  1) wildcard_2025.pfx
  2) exchange_cert.cer
  3) apache_web.pem
  A) Import ALL

  Select file number (A = all, 0 = cancel):
```

> **Note**: Requires `cifs-utils` package. The share is mounted read-only and unmounted automatically after import.

#### 2) Network share (NFS)

```
  NFS export (e.g. nfs-server:/export/certs): nfs01:/share/certs
  Mounting nfs01:/share/certs... ✔ Mounted
```

> **Note**: Requires `nfs-common` package.

#### 3) Download from URL

```
  Certificate URL: https://pki.internal/certs/root-ca.pem
  Downloading... ✔
  Validating certificate... ✔
  ✔ Imported: root-ca.pem
```

Uses `curl` if available, falls back to `wget`.

#### 4) Paste PEM content

For environments where you only have console access:

```
  Certificate name (e.g. wildcard_domain_com): my_server_cert

  Paste the PEM certificate below (including BEGIN/END lines).
  When done, type END on a new line and press Enter.

  -----BEGIN CERTIFICATE-----
  MIIDxTCCAq2gAwIBAgIQA...
  -----END CERTIFICATE-----
  END

  Validating certificate... ✔
  ✔ Imported: my_server_cert.pem
```

### Supported formats

| Format | Extensions | Handling |
|--------|-----------|----------|
| **PEM** | `.pem`, `.crt`, `.cer` | Validated and copied directly |
| **DER** | `.der` | Auto-detected and converted to PEM |
| **PKCS#12** | `.pfx`, `.p12` | Prompts for password, extracts public certificate only (private key is **never** stored) |

---

## ⏱ Auto-Refresh

The dashboard refreshes automatically at the configured interval. During the countdown, pressing any key immediately opens the menu for interaction.

### Changing the interval

Select option `7`:

```
  ── Configure auto-refresh ──

  Current: 5m

  Choose an interval:

  1)  30 seconds       (testing)
  2)   1 minute
  3)   5 minutes        (default)
  4)  15 minutes
  5)  30 minutes
  6)   1 hour
  7)   6 hours
  8)  12 hours
  9)  24 hours
  C)  Custom            (enter seconds manually)
  0)  Disable           (manual only)
```

The setting is saved to `.refresh_interval` and persists between executions.

---

## 📊 Status Thresholds

| Status | Color | Condition |
|--------|-------|-----------|
| ✔ **OK** | 🟢 Green | More than 30 days remaining |
| ● **WARNING** | 🟠 Orange | 30 days or less remaining |
| ▲ **ALERT** | 🔴 Red | 15 days or less remaining |
| ✗ **EXPIRED** | 🔴 Red | Certificate has expired |
| ✗ **ERROR** | 🔴 Red | Could not connect or read certificate |

Thresholds are defined at the top of the script and can be customized:

```bash
WARN_DAYS=30
CRIT_DAYS=15
```

---

## 📄 Export Report

Option `6` generates a plain-text report with all certificate statuses:

```
=============================================
 CERTIFICATE REPORT - 2026-03-05 14:30
 Host: monitoring-server
=============================================

=== REMOTE SERVERS ===

--- APACHE ---
[OK      ] web01.domain.com:443                  | Days: 185   | Sep 04 23:59:59 2026 GMT
[ALERT   ] web02.domain.com:443                  | Days: 8     | Mar 13 23:59:59 2026 GMT

--- IIS ---
[OK      ] portal.corp.local:443                 | Days: 292   | Dec 20 12:00:00 2026 GMT

=== LOCAL CERTIFICATES ===
Store: /opt/cert-monitor/certs/

[OK      ] wildcard_acme_corp.pem                | Days: 364   | Mar 05 22:15:00 2027 GMT
[WARNING ] webserver_intranet.crt                | Days: 24    | Mar 30 22:15:00 2026 GMT
[EXPIRED ] expired_legacy.pem                    | Days: -2    | Mar 03 22:15:03 2026 GMT
```

Reports are saved as `report_YYYYMMDD_HHMMSS.txt` in the script directory.

---

## 🧪 Test Certificates

A helper script is included to generate example certificates in all supported formats:

```bash
sudo ./generate_example_certs.sh
```

This creates 6 test certificates covering different formats and expiry states:

| File | Format | Days | Status | Notes |
|------|--------|------|--------|-------|
| `wildcard_acme_corp.pem` | PEM | 365 | ✔ OK | RSA 2048, wildcard with SANs |
| `webserver_intranet.crt` | CRT | 25 | ● WARNING | Within 30-day threshold |
| `exchange_mail.cer` | CER | 10 | ▲ ALERT | RSA 4096, within 15-day threshold |
| `appliance_fw.der` | DER | 200 | ✔ OK | Binary format, auto-converted on import |
| `iis_portal.pfx` | PFX | 5 | ▲ ALERT | Password: `Test1234` |
| `expired_legacy.pem` | PEM | -2 | ✗ EXPIRED | Already expired |

To import the test certificates into the tool:

```bash
# Copy all except PFX directly to the store
cp /opt/cert-monitor/example-certs/*.pem /opt/cert-monitor/certs/
cp /opt/cert-monitor/example-certs/*.crt /opt/cert-monitor/certs/
cp /opt/cert-monitor/example-certs/*.cer /opt/cert-monitor/certs/
cp /opt/cert-monitor/example-certs/*.der /opt/cert-monitor/certs/

# Import PFX via menu (option 8 → 1)
# Path: /opt/cert-monitor/example-certs/iis_portal.pfx
# Password: Test1234
```

> **Note**: The expired certificate requires OpenSSL 3.x (`-not_before`/`-not_after` flags) or `faketime` for OpenSSL 1.x. The script handles both cases automatically.

---

## 🔧 Automation with Cron

You can schedule the export report for unattended monitoring:

```bash
# Generate a report every day at 8:00 AM
0 8 * * * /opt/cert-monitor/cert_manager.sh --export-only 2>/dev/null

# Or use the dashboard in a screen/tmux session for persistent monitoring
tmux new-session -d -s certmon '/opt/cert-monitor/cert_manager.sh --refresh 3600'
```

---

## 📂 Repository Structure

```
cert-monitor/
├── cert_manager.sh              # Main monitoring tool
├── generate_example_certs.sh    # Test certificate generator
├── LICENSE                      # CertManager Community License
└── README.md                    # This file
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests. Please keep the original attribution as required by the license.

---

## ☕ Support

If you find this tool useful and your organization has **50 or more employees**, a small contribution is appreciated:

<a href="https://buymeacoffee.com/alexmilla" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>

| Use case | Cost |
|----------|------|
| Personal use | ✅ Free |
| Organizations < 50 employees | ✅ Free |
| Organizations ≥ 50 employees | ☕ [Small contribution](https://buymeacoffee.com/alexmilla) |

---

## 📜 License

This project is licensed under the **CertManager Community License v1.0**.

- ✅ **Free** for individuals, personal use, and educational purposes
- ✅ **Free** for organizations with fewer than 50 employees
- ☕ **Contribution required** for organizations with 50+ employees — via [Buy Me a Coffee](https://buymeacoffee.com/alexmilla)
- ✅ Modify and redistribute with attribution

**Author**: Alex Milla — [alexmilla.dev](https://alexmilla.dev)

See [LICENSE](LICENSE) for full terms.

---

## 📬 Contact

- Website: [alexmilla.dev](https://alexmilla.dev)
- GitHub: [github.com/alex-milla](https://github.com/alex-milla)
- Support: [buymeacoffee.com/alexmilla](https://buymeacoffee.com/alexmilla)
