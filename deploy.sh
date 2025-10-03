#!/bin/bash

set -e  # Exit on any error

echo "=== DHCP Manager Deployment Script ==="
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

APP_SOURCE="/app"
FRONTEND_SOURCE="/app/frontend"
WEB_ROOT="/var/www/dhcp-manager"
BACKEND_USER="dhcp-manager"
PYTHON_VERSION="python3"

echo "Step 1: Installing system dependencies..."
apt-get update
apt-get install -y python3.11 python3.11-venv nginx isc-dhcp-server curl

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
echo "Step 6: Configuring nginx..."
cat > /etc/nginx/sites-available/dhcp-manager <<'EOF'
server {
    listen 80;
    server_name _;

    root /var/www/dhcp-manager;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

ln -sf /etc/nginx/sites-available/dhcp-manager /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo ""
echo "Step 7: Configuring backend systemd service..."
# Generate random secret key
SECRET_KEY=$(openssl rand -hex 32)

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
ExecStart=/opt/dhcp-manager/backend/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 --timeout 120 --access-logfile - --error-logfile - "app:create_app()"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo "Step 8: Detecting network interface and configuring DHCP..."

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

# Create dhcpd.conf if it doesn't exist
if [ ! -f /etc/dhcp/dhcpd.conf ]; then
    echo "Creating dhcpd.conf with subnet configuration..."
    mkdir -p /etc/dhcp
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

# Static host reservations will appear below
DHCPEOF
else
    echo "dhcpd.conf already exists, skipping subnet configuration"
    echo "WARNING, If the alreadt existing dhcpd.conf does not contain a valid configuration e.g. a default subnet the service will fail to start"
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
echo "Step 9: Configuring DHCP file permissions..."

# Create backup directory
mkdir -p /etc/dhcp/backups
chown "$BACKEND_USER":"$BACKEND_USER" /etc/dhcp/backups
chmod 770 /etc/dhcp/backups

# Allow backend user to read/write dhcpd.conf
# Owner must remain root, only change group
chown root:"$BACKEND_USER" /etc/dhcp/dhcpd.conf
chmod 660 /etc/dhcp/dhcpd.conf

# Ensure /etc/dhcp directory allows writing temp files
chown root:"$BACKEND_USER" /etc/dhcp
chmod 775 /etc/dhcp

# Allow backend user to restart DHCP service via sudoers
cat > /etc/sudoers.d/dhcp-manager <<EOF
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart isc-dhcp-server.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl status isc-dhcp-server.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active isc-dhcp-server.service
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart isc-dhcp-server
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl status isc-dhcp-server
$BACKEND_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active isc-dhcp-server
$BACKEND_USER ALL=(ALL) NOPASSWD: /usr/sbin/dhcpd -t -cf /etc/dhcp/dhcpd.conf
EOF
chmod 440 /etc/sudoers.d/dhcp-manager

# Create polkit rule to allow dhcp-manager to control isc-dhcp-server without authentication
mkdir -p /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/50-dhcp-manager.rules <<'POLKITEOF'
/* Allow dhcp-manager user to manage isc-dhcp-server service */
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.user == "dhcp-manager") {
        var unit = action.lookup("unit");
        if (unit == "isc-dhcp-server.service") {
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
echo "Step 10: Starting services..."
systemctl daemon-reload
systemctl enable dhcp-manager
systemctl start dhcp-manager
systemctl enable nginx
systemctl enable isc-dhcp-server

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Services status:"
systemctl status dhcp-manager --no-pager || true
echo ""
systemctl status nginx --no-pager || true
echo ""
echo "Access the application at: http://$(hostname -I | awk '{print $1}')"
echo ""
echo "Useful commands:"
echo "  - View backend logs: journalctl -u dhcp-manager -f"
echo "  - View DHCP logs: journalctl -u isc-dhcp-server -f"
echo "  - Restart backend: systemctl restart dhcp-manager"
