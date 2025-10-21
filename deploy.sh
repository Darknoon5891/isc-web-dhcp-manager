#!/bin/bash

set -e  # Exit on any error

echo "=== DHCP Manager Deployment Script ==="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Detect if running from stdin (piped from curl | bash)
if [ ! -f "$0" ] || [ "$0" = "bash" ] || [ "$0" = "-bash" ] || [ "$0" = "sh" ] || [ "$0" = "-sh" ]; then
    echo "=== Bootstrap Mode ==="
    echo "Cloning repository..."
    echo ""

    # Check for git
    if ! command -v git >/dev/null 2>&1; then
        echo "Git not found. Installing git..."
        apt-get update -qq
        apt-get install -y git
    fi

    # Define repository URL and branch (can be overridden via environment variables) (will clone main by default)
    REPO_URL="${DHCP_MANAGER_REPO_URL:-https://github.com/Darknoon5891/isc-web-dhcp-manager.git}"
    REPO_BRANCH="${DHCP_MANAGER_BRANCH:-main}"

    # Create temp directory with unique name using mktemp for guaranteed uniqueness
    TEMP_DIR="$(mktemp -d -t dhcp-manager-install-XXXXXX)"
    trap "rm -rf '$TEMP_DIR'" EXIT  # Ensure cleanup on exit

    echo "Repository: $REPO_URL"
    echo "Branch: $REPO_BRANCH"
    echo "Cloning to: $TEMP_DIR/repo"
    echo ""

    # Clone repository
    if ! git clone --depth=1 --branch "$REPO_BRANCH" "$REPO_URL" "$TEMP_DIR/repo"; then
        echo ""
        echo "ERROR: Failed to clone repository"
        echo "Please check:"
        echo "  1. Repository URL is correct"
        echo "  2. Branch name is correct"
        echo "  3. You have internet connectivity"
        exit 1
    fi

    echo ""
    echo "Repository cloned successfully"
    echo "Re-executing deployment from cloned directory..."
    echo "========================================"
    echo ""

    # Re-execute the script from cloned directory
    cd "$TEMP_DIR/repo"
    if [ -f "$TEMP_DIR/repo/deploy.sh" ]; then
        bash "$TEMP_DIR/repo/deploy.sh"
        EXIT_CODE=$?
    else
        echo "ERROR: deploy.sh not found in cloned repository at $TEMP_DIR/repo"
        EXIT_CODE=1
    fi

    # Leave temp directory so trap can clean it up
    cd /

    # Cleanup happens via trap on EXIT
    # Exit with the same code as the actual deployment
    exit $EXIT_CODE
fi

# Auto-detect script directory (when running from local file)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_SOURCE="${SCRIPT_DIR}"
CONFIG_SOURCE="${APP_SOURCE}/config"
FRONTEND_SOURCE="${APP_SOURCE}/frontend"
WEB_ROOT="/var/www/dhcp-manager"
BACKEND_USER="dhcp-manager"
PYTHON_VERSION="python3"

# TLS/SSL Configuration
CERT_DAYS=3650  # 10 years
TLS_CERT_PATH="/etc/nginx/ssl/dhcp-manager.crt"
TLS_KEY_PATH="/etc/nginx/ssl/dhcp-manager.key"
TLS_DIR="/etc/nginx/ssl"

# Check if ISC DHCP Server is already installed before we install packages
# This helps us determine if the config file is from a previous installation
DHCP_WAS_INSTALLED=false
if systemctl list-unit-files 2>/dev/null | grep -q 'isc-dhcp-server.service'; then
    DHCP_WAS_INSTALLED=true
fi

echo "Step 1: Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv nginx curl openssl
# install isc-dhcp-server as a special case as it writes a default/invalid config and then attempts to start
# redirect stdout to null until we can write the correct config: 
sudo apt-get install -y isc-dhcp-server 1>/dev/null

echo ""
echo "Step 2: Creating backend service user..."
if ! id "$BACKEND_USER" >/dev/null 2>&1; then
    useradd -r -s /bin/bash -d /opt/dhcp-manager "$BACKEND_USER"
fi

echo ""
echo "Step 3: Setting up backend..."
mkdir -p /opt/dhcp-manager
cp -r "$APP_SOURCE/backend" /opt/dhcp-manager/
chown -R "$BACKEND_USER":"$BACKEND_USER" /opt/dhcp-manager

# Create virtual environment and install dependencies
cd /opt/dhcp-manager/backend
sudo -u "$BACKEND_USER" $PYTHON_VERSION -m venv venv
sudo -u "$BACKEND_USER" venv/bin/pip install -r requirements.txt
sudo -u "$BACKEND_USER" venv/bin/pip install gunicorn

echo ""
echo "Step 4: Setting up web root..."
mkdir -p "$WEB_ROOT"
cp -r "$FRONTEND_SOURCE/build/"* "$WEB_ROOT/"
chown -R www-data:www-data "$WEB_ROOT"

echo ""

echo "Step 6: Generating self-signed SSL certificate..."

# Get server FQDN and hostname
SERVER_FQDN=$(hostname -f)
SERVER_HOSTNAME=$(hostname -s)
SERVER_IP=$(hostname -I | awk '{print $1}')

echo "Server FQDN: $SERVER_FQDN"
echo "Server Hostname: $SERVER_HOSTNAME"
echo "Server IP: $SERVER_IP"

# Create TLS directory
mkdir -p "$TLS_DIR"

# Create OpenSSL config for SAN (Subject Alternative Names)
cat > /tmp/openssl-san.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
O=DHCP Manager
CN=$SERVER_FQDN

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_FQDN
DNS.2 = $SERVER_HOSTNAME
DNS.3 = localhost
IP.1 = $SERVER_IP
IP.2 = 127.0.0.1
EOF

# Generate self-signed certificate with SAN
openssl req -x509 -nodes -days $CERT_DAYS \
    -newkey rsa:2048 \
    -keyout "$TLS_KEY_PATH" \
    -out "$TLS_CERT_PATH" \
    -config /tmp/openssl-san.cnf \
    -extensions req_ext 2>/dev/null

# Set proper permissions
chmod 600 "$TLS_KEY_PATH"
chmod 644 "$TLS_CERT_PATH"

# Clean up temp config
rm -f /tmp/openssl-san.cnf

echo "SSL certificate generated:"
echo "  Certificate: $TLS_CERT_PATH"
echo "  Private Key: $TLS_KEY_PATH"
echo "  Common Name: $SERVER_FQDN"
echo "  SAN: $SERVER_FQDN, $SERVER_HOSTNAME, localhost"
echo ""
echo "WARNING: This is a self-signed certificate."
echo "Browsers will show security warnings on first access."
echo ""

echo "Step 7: Configuring nginx..."

# Check if port 443 is available, fall back to 8000 if in use
if ss -tuln 2>/dev/null | grep -q ':443 ' || netstat -tuln 2>/dev/null | grep -q ':443 '; then
    HTTPS_PORT=8000
    REDIRECT_PORT=":8000"
    echo "Port 443 is in use, using port 8000 for HTTPS"
else
    HTTPS_PORT=443
    REDIRECT_PORT=""
    echo "Port 443 is available, using it for HTTPS"
fi

cat > /etc/nginx/sites-available/dhcp-manager <<EOF
# HTTP server - redirect to HTTPS
server {
    listen 80;
    server_name _;

    # Redirect all HTTP traffic to HTTPS
    return 301 https://\$host$REDIRECT_PORT\$request_uri;
}

# HTTPS server
server {
    listen $HTTPS_PORT ssl http2;
    server_name _;

    # SSL Certificate (self-signed)
    ssl_certificate $TLS_CERT_PATH;
    ssl_certificate_key $TLS_KEY_PATH;

    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    root /var/www/dhcp-manager;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_redirect off;

        # Timeouts for API requests
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/dhcp-manager /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo ""
echo "Step 8: Configuring backend systemd service..."

# Generate random secret key
SECRET_KEY=$(openssl rand -hex 32)

# Generate random password for authentication (using venv's bcrypt)
echo "Generating authentication password..."
DEFAULT_PASSWORD=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
DEFAULT_PASSWORD_HASH=$(sudo -u "$BACKEND_USER" bash -c "source /opt/dhcp-manager/backend/venv/bin/activate && python3 -c \"import bcrypt; print(bcrypt.hashpw(b'$DEFAULT_PASSWORD', bcrypt.gensalt(rounds=12)).decode('utf-8'))\"")


cat > /etc/systemd/system/dhcp-manager.service <<EOF
[Unit]
Description=DHCP Manager Backend
After=network.target

[Service]
Type=simple
User=$BACKEND_USER
Group=$BACKEND_USER
WorkingDirectory=/opt/dhcp-manager/backend
Environment="PATH=/opt/dhcp-manager/backend/venv/bin"
Environment="SECRET_KEY=$SECRET_KEY"
Environment="FLASK_ENV=production"
ExecStart=/opt/dhcp-manager/backend/venv/bin/gunicorn -c /opt/dhcp-manager/backend/gunicorn.conf.py "app:create_app()"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo "Configuring of backend systemd service completed"

echo ""
echo "Step 9: Creating application configuration directory..."

# Create /etc/isc-web-dhcp-manager directory for app config
mkdir -p /etc/isc-web-dhcp-manager
mkdir -p /etc/isc-web-dhcp-manager/backups
chown -R "$BACKEND_USER":"$BACKEND_USER" /etc/isc-web-dhcp-manager
chmod 750 /etc/isc-web-dhcp-manager
chmod 770 /etc/isc-web-dhcp-manager/backups

# Copy configuration schema to /etc
cp "$CONFIG_SOURCE/config_schema.json" /etc/isc-web-dhcp-manager/config_schema.json
chown "$BACKEND_USER":"$BACKEND_USER" /etc/isc-web-dhcp-manager/config_schema.json
chmod 644 /etc/isc-web-dhcp-manager/config_schema.json

# Create application config file
cat > /etc/isc-web-dhcp-manager/config.conf <<APPCONFEOF
# ISC Web DHCP Manager Configuration
#
# IMPORTANT: When adding new configuration options, update the schema file:
# /etc/isc-web-dhcp-manager/config_schema.json

# API Prefix:
API_PREFIX=/api

# Flask Environment
FLASK_ENV=production

# Security
SECRET_KEY=$SECRET_KEY

# DHCP Configuration File Path
DHCP_CONFIG_PATH=/etc/dhcp/dhcpd.conf

# DHCP Backup Directory
DHCP_BACKUP_DIR=/etc/isc-web-dhcp-manager/backups

# DHCP Service Name
DHCP_SERVICE_NAME=isc-dhcp-server

# DHCP Leases File Path
DHCP_LEASES_PATH=/var/lib/dhcp/dhcpd.leases

# Application Settings
ALLOW_SERVICE_RESTART=true
MAX_HOSTNAME_LENGTH=255
MAX_BACKUPS=10
REQUIRE_SUDO=true
MAX_CONTENT_LENGTH=1048576

# CORS Settings
CORS_ORIGINS=https://$SERVER_FQDN,https://$SERVER_IP,https://$SERVER_HOSTNAME,https://localhost

# Logging
LOG_LEVEL=INFO
LOGGING_PATH=/var/log/isc-web-dhcp-manager


# TLS Configuration
TLS_CERTIFICATE_PATH=$TLS_CERT_PATH
TLS_PRIVATE_KEY_PATH=$TLS_KEY_PATH
TLS_ENABLED=true

# Authentication
AUTH_ENABLED=true
AUTH_PASSWORD_HASH=$DEFAULT_PASSWORD_HASH
AUTH_TOKEN_EXPIRY_HOURS=24

# Debug Mode
FLASK_DEBUG=false
APPCONFEOF

chown "$BACKEND_USER":"$BACKEND_USER" /etc/isc-web-dhcp-manager/config.conf
chmod 640 /etc/isc-web-dhcp-manager/config.conf

# Create logging directory
mkdir -p /var/log/isc-web-dhcp-manager
chown "$BACKEND_USER":"$BACKEND_USER" /var/log/isc-web-dhcp-manager
chmod 750 /var/log/isc-web-dhcp-manager

echo "Created /etc/isc-web-dhcp-manager for application configuration"

echo ""
echo "Step 10: Detecting network interface and configuring DHCP..."

# Detect the primary network interface (excluding loopback)
INTERFACE=$(ip route | grep default | head -n1 | awk '{print $5}')
if [ -z "$INTERFACE" ]; then
    echo "Warning: Could not detect default network interface, using first available interface"
    INTERFACE=$(ip link show | grep -v "lo:" | grep "state UP" | head -n1 | awk -F': ' '{print $2}')
fi

if [ -z "$INTERFACE" ]; then
    echo "ERROR: No network interface found!"
    exit 1
fi

echo "Detected network interface: $INTERFACE"

# Get network information for the interface
INTERFACE_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
INTERFACE_NETMASK=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | cut -d'/' -f2)

if [ -z "$INTERFACE_IP" ]; then
    echo "ERROR: Could not detect IP address for interface $INTERFACE"
    exit 1
fi

# Convert CIDR to netmask
case $INTERFACE_NETMASK in
    24) NETMASK="255.255.255.0" ;;
    16) NETMASK="255.255.0.0" ;;
    8) NETMASK="255.0.0.0" ;;
    *) NETMASK="255.255.255.0" ;;
esac

# Calculate network address
i1=$(echo "$INTERFACE_IP" | cut -d. -f1)
i2=$(echo "$INTERFACE_IP" | cut -d. -f2)
i3=$(echo "$INTERFACE_IP" | cut -d. -f3)
i4=$(echo "$INTERFACE_IP" | cut -d. -f4)

m1=$(echo "$NETMASK" | cut -d. -f1)
m2=$(echo "$NETMASK" | cut -d. -f2)
m3=$(echo "$NETMASK" | cut -d. -f3)
m4=$(echo "$NETMASK" | cut -d. -f4)

NETWORK="$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$((i4 & m4))"

# Calculate router (gateway) - typically .1
n1=$(echo "$NETWORK" | cut -d. -f1)
n2=$(echo "$NETWORK" | cut -d. -f2)
n3=$(echo "$NETWORK" | cut -d. -f3)
n4=$(echo "$NETWORK" | cut -d. -f4)

ROUTER="$n1.$n2.$n3.1"

# Calculate DHCP range - .100 to .200
RANGE_START="$n1.$n2.$n3.100"
RANGE_END="$n1.$n2.$n3.200"

echo "Network configuration:"
echo "  Interface: $INTERFACE"
echo "  Network: $NETWORK"
echo "  Netmask: $NETMASK"
echo "  Router: $ROUTER"
echo "  DHCP Range: $RANGE_START - $RANGE_END"

echo ""

# Intelligent DHCP config creation - handles multiple scenarios
mkdir -p /etc/dhcp
SHOULD_CREATE_CONFIG=false
CONFIG_DECISION_REASON=""

if [ ! -f /etc/dhcp/dhcpd.conf ]; then
    # Scenario 1: No config file exists at all
    SHOULD_CREATE_CONFIG=true
    CONFIG_DECISION_REASON="Config file does not exist"

elif [ "$DHCP_WAS_INSTALLED" = false ]; then
    # ISC DHCP was just installed by this script - check if config is usable
    echo "Analyzing freshly installed DHCP config..."

    # Count non-comment, non-empty lines (active configuration)
    ACTIVE_LINES=$(grep -v '^#' /etc/dhcp/dhcpd.conf | grep -v '^[[:space:]]*$' | wc -l)

    # Check if config contains a subnet declaration (required for valid config)
    HAS_SUBNET=$(grep -c '^[[:space:]]*subnet' /etc/dhcp/dhcpd.conf 2>/dev/null || true)
    HAS_SUBNET=${HAS_SUBNET:-0}

    if [ "$HAS_SUBNET" -eq 0 ]; then
        # Scenario 2: Fresh install without subnet declaration (default ISC install)
        # Default has ~5 active lines but no subnet = not usable
        SHOULD_CREATE_CONFIG=true
        CONFIG_DECISION_REASON="Fresh install with default config (no subnet declaration, $ACTIVE_LINES active lines)"
    else
        # Has subnet declaration - could be from previous installation or manual edit
        # Check if it looks like it was manually created (has host declarations or custom settings)
        HAS_HOST_DECLARATIONS=$(grep -c '^[[:space:]]*host[[:space:]]' /etc/dhcp/dhcpd.conf 2>/dev/null || true)
        HAS_HOST_DECLARATIONS=${HAS_HOST_DECLARATIONS:-0}

        if [ "$HAS_HOST_DECLARATIONS" -gt 0 ]; then
            # Scenario 3: Has subnet AND host declarations - definitely a real config
            SHOULD_CREATE_CONFIG=false
            CONFIG_DECISION_REASON="Existing config with $HAS_SUBNET subnet(s) and $HAS_HOST_DECLARATIONS host(s) - preserving"
        else
            # Scenario 4: Has subnet but no hosts - check if subnet matches our detected network
            # If it matches, likely from a previous run of this script
            # If different, preserve it as user-configured
            EXISTING_SUBNET=$(grep '^[[:space:]]*subnet' /etc/dhcp/dhcpd.conf | head -n1 | awk '{print $2}')

            if [ "$EXISTING_SUBNET" = "$NETWORK" ]; then
                # Same subnet as we would create - safe to recreate
                SHOULD_CREATE_CONFIG=true
                CONFIG_DECISION_REASON="Config has our auto-generated subnet ($NETWORK) but no hosts - recreating"
            else
                # Different subnet - user configured, preserve it
                SHOULD_CREATE_CONFIG=false
                CONFIG_DECISION_REASON="User-configured subnet ($EXISTING_SUBNET) found - preserving"
            fi
        fi
    fi
else
    # Scenario 5: ISC DHCP was already installed before running this script
    SHOULD_CREATE_CONFIG=false
    CONFIG_DECISION_REASON="Service was already installed, preserving existing config"
fi

echo "Config decision: $CONFIG_DECISION_REASON"

if [ "$SHOULD_CREATE_CONFIG" = true ]; then
    # Backup existing config if it exists
    if [ -f /etc/dhcp/dhcpd.conf ]; then
        BACKUP_FILE="/etc/isc-web-dhcp-manager/backups/dhcpd.conf.backup.$(date +%Y%m%d_%H%M%S)"
        echo "Backing up existing config to: $BACKUP_FILE"
        cp /etc/dhcp/dhcpd.conf "$BACKUP_FILE"
    fi

    echo "Creating new dhcpd.conf with subnet configuration..."
    cat > /etc/dhcp/dhcpd.conf <<DHCPEOF
# DHCP Server Configuration
default-lease-time 600;
max-lease-time 7200;

# Subnet configuration for $INTERFACE
subnet $NETWORK netmask $NETMASK {
  range $RANGE_START $RANGE_END;
  option routers $ROUTER;
  option subnet-mask $NETMASK;
  option domain-name-servers 8.8.8.8, 8.8.4.4;
}

DHCPEOF
    echo "dhcpd.conf created successfully"
else
    echo "Keeping existing dhcpd.conf"
    echo "WARNING: If the existing config is invalid, the DHCP service will fail to start"
fi

# Configure ISC DHCP Server interface
echo "Configuring ISC DHCP Server to listen on $INTERFACE..."
cat > /etc/default/isc-dhcp-server <<DHCPDEFEOF
# Defaults for isc-dhcp-server (sourced by /etc/init.d/isc-dhcp-server)

# Path to dhcpd's config file (default: /etc/dhcp/dhcpd.conf).
#DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
#DHCPDv6_CONF=/etc/dhcp/dhcpd6.conf

# Path to dhcpd's PID file (default: /var/run/dhcpd.pid).
#DHCPDv4_PID=/var/run/dhcpd.pid
#DHCPDv6_PID=/var/run/dhcpd6.pid

# Additional options to start dhcpd with.
#	Don't use options -cf or -pf here; use DHCPD_CONF/ DHCPD_PID instead
#OPTIONS=""

# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?
#	Separate multiple interfaces with spaces, e.g. "eth0 eth1".
INTERFACESv4="$INTERFACE"
INTERFACESv6=""
DHCPDEFEOF

echo "DHCP configuration completed"
echo ""
echo "Step 11: Configuring DHCP file permissions..."

# Allow backend user to read/write dhcpd.conf
# Owner must remain root, only change group
chown root:"$BACKEND_USER" /etc/dhcp/dhcpd.conf
chmod 660 /etc/dhcp/dhcpd.conf

# Ensure /etc/dhcp directory allows writing temp files
chown root:"$BACKEND_USER" /etc/dhcp
chmod 775 /etc/dhcp

# Allow backend user to restart DHCP service and backend service via sudoers
cat > /etc/sudoers.d/dhcp-manager <<EOF
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart isc-dhcp-server.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl status isc-dhcp-server.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active isc-dhcp-server.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart isc-dhcp-server
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl status isc-dhcp-server
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active isc-dhcp-server
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart dhcp-manager.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl status dhcp-manager.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active dhcp-manager.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl status nginx.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl status nginx
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active nginx.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active nginx
$BACKEND_USER ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
$BACKEND_USER ALL=(ALL) NOPASSWD: /usr/sbin/dhcpd -t -cf /etc/dhcp/dhcpd.conf
EOF
chmod 440 /etc/sudoers.d/dhcp-manager

# Create polkit rule to allow dhcp-manager to control isc-dhcp-server and dhcp-manager services without authentication
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/50-dhcp-manager.rules <<'POLKITEOF'
/* Allow dhcp-manager user to manage isc-dhcp-server and dhcp-manager services */
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.user == "dhcp-manager") {
        var unit = action.lookup("unit");
        if (unit == "isc-dhcp-server.service" || unit == "dhcp-manager.service") {
            return polkit.Result.YES;
        }
    }
});

polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-unit-files" &&
        subject.user == "dhcp-manager") {
        return polkit.Result.YES;
    }
});
POLKITEOF
chmod 644 /etc/polkit-1/rules.d/50-dhcp-manager.rules

echo ""
echo "Step 12: Starting services..."
systemctl daemon-reload
systemctl enable dhcp-manager
systemctl start dhcp-manager
systemctl enable nginx
systemctl enable isc-dhcp-server

# If we recreated the DHCP config, restart the service to apply changes
if [ "$SHOULD_CREATE_CONFIG" = true ]; then
    echo "Restarting ISC DHCP Server with new configuration..."
    systemctl restart isc-dhcp-server
fi

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Services status:"
systemctl status dhcp-manager --no-pager --lines=0 || true
echo ""
systemctl status nginx --no-pager --lines=0 || true
echo ""
echo "Restarting DHCP Manager backend to apply all changes..."
systemctl restart dhcp-manager
echo ""
echo "=========================================="
echo "Access the application at: https://$(hostname -I | awk '{print $1}')$REDIRECT_PORT"
echo "  or: https://$(hostname -f)$REDIRECT_PORT"
echo "=========================================="
echo ""
echo "IMPORTANT: Self-signed SSL certificate in use"
echo "  Your browser will show a security warning on first access"
echo "  This is expected. Click 'Advanced' and 'Proceed' to continue"
echo ""
echo "SSL Certificate Details:"
echo "  Certificate: $TLS_CERT_PATH"
echo "  Private Key: $TLS_KEY_PATH"
echo "  Common Name: $(hostname -f)"
echo "  Validity: 10 years"
echo ""
echo "=========================================="
echo "AUTHENTICATION CREDENTIALS"
echo "=========================================="
echo "  Username: (none - password only)"
echo "  Password: $DEFAULT_PASSWORD"
echo ""
echo "IMPORTANT: Change this password immediately after login!"
echo "  - Go to App Settings > Authentication"
echo "  - Or re-run this deployment script to generate a new password"
echo "=========================================="
echo ""

echo ""
echo "Useful commands:"
echo "  - View backend logs: journalctl -u dhcp-manager -f"
echo "  - View DHCP logs: journalctl -u isc-dhcp-server -f"
echo "  - Restart backend: systemctl restart dhcp-manager"
echo "  - View certificate: openssl x509 -in $TLS_CERT_PATH -text -noout"
