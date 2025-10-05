# ISC Web DHCP Configuration Manager

A production-ready web-based interface for managing ISC DHCP Server configuration. Provides comprehensive management of DHCP hosts, subnets, zones, leases, and global configuration with TLS/HTTPS support and JWT authentication.

Built and tested on **Debian 12 (amd64)** with **Python 3.11**

## Features

### DHCP Management

- **Host Reservations**: Add, edit, delete, and search static DHCP host reservations with MAC and IP bindings
- **Subnet Management**: Configure DHCP subnets with IP ranges, routers, DNS servers, and custom options
- **PTR Zone Management**: Configure dynamic DNS reverse zones for automatic PTR record updates
- **Global Configuration**: Manage lease times, authoritative mode, DDNS settings, NTP servers, and ping checking
- **Lease Viewing**: Real-time view of active and expired leases with search and 30-second auto-refresh

### System Management

- **Service Control**: Start, stop, and restart ISC DHCP Server and Nginx from the web interface
- **Service Status**: Real-time monitoring of ISC DHCP Server and Nginx with color-coded status badges
- **Configuration Validation**: Test DHCP configuration syntax before applying changes
- **Backup Management**: Automatic backups before configuration changes, viewable backup list
- **Configuration Viewer**: View raw DHCP configuration file with syntax highlighting

### Security & Administration

- **JWT Authentication**: Secure token-based login system with 24-hour expiration
- **Password Management**: Change password from web interface (automatically restarts backend)
- **TLS/HTTPS**: Self-signed or custom certificate support with certificate information display
- **App Configuration**: Web-based settings editor with schema validation and masked sensitive values

## Quick Start

### Automated Deployment (Recommended)

The deployment script provides complete automated installation:

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd isc-web-dhcp-manager
   ```

2. **Run the deployment script as root:**
   ```bash
   sudo ./deploy.sh
   ```

The script automatically:

- Detects its directory for flexible deployment locations
- Installs system dependencies (Python 3.11, Nginx, ISC DHCP Server, Node.js)
- Creates dedicated `dhcp-manager` system user with restricted permissions
- Sets up backend with Gunicorn WSGI server and systemd service
- Builds and deploys React frontend to `/var/www/dhcp-manager`
- Generates 10-year self-signed TLS certificate with proper SANs
- Configures Nginx with HTTPS (TLS 1.2/1.3), security headers, and HTTP→HTTPS redirect
- Auto-detects port availability: uses port 443 if available, falls back to port 8000 if 443 is occupied
- Sets up passwordless sudo for specific service management commands
- Creates application configuration in `/opt/dhcp-manager/config/`
- Intelligently handles DHCP configuration:
  - Preserves existing configs with host declarations
  - Recreates default/invalid configs from fresh installs
  - Auto-detects network interface and subnet
  - Configures DHCP range `.100-.200` by default
- Generates default password (`admin`) in bcrypt-hashed format
- Starts all services and verifies status

**Post-Deployment:**

1. Access the web interface at `https://<server-ip>` (or `https://<server-ip>:8000` if port 443 was in use)
   - The deployment script automatically uses port 443 if available, or falls back to port 8000 if port 443 is occupied
   - Accept self-signed certificate warning in browser
2. Login with password: `admin`
3. **Immediately change the default password** in App Settings tab
4. Optionally configure custom TLS certificate paths in App Settings
5. Review and adjust DHCP configuration as needed

**Important:**

- Application runs as dedicated `dhcp-manager` user (non-root)
- Config stored in `/opt/dhcp-manager/config/config.json`
- Backups stored in `/opt/dhcp-manager/backups/`
- Frontend served from `/var/www/dhcp-manager`
- Backend runs on `127.0.0.1:5000` (proxied by Nginx)
- Logs: `sudo journalctl -u dhcp-manager -f`

### Manual Development Setup

For local development and testing:

#### Backend Setup

1. Navigate to backend directory:

   ```bash
   cd backend
   ```

2. Create and activate virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run Flask development server:
   ```bash
   python app.py
   ```
   Backend runs on `http://localhost:5000`

#### Frontend Setup

1. Navigate to frontend directory:

   ```bash
   cd frontend
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Start development server:
   ```bash
   npm start
   ```
   Frontend runs on `http://localhost:3000` and proxies API requests to port 5000

## Project Structure

```
isc-web-dhcp-manager/
├── backend/
│   ├── app.py                 # Main Flask application with all API routes
│   ├── dhcp_parser.py         # DHCP config parser (hosts, subnets, zones, global)
│   ├── lease_parser.py        # DHCP lease file parser
│   ├── config_manager.py      # App configuration management
│   ├── auth_manager.py        # JWT authentication and password hashing
│   ├── tls_manager.py         # TLS certificate management
│   └── requirements.txt       # Python dependencies
├── config/
│   └── config_schema.json     # Application settings schema with validation
├── frontend/
│   ├── public/
│   │   └── index.html         # HTML template
│   ├── src/
│   │   ├── App.tsx            # Main app with tab navigation and auth
│   │   ├── components/        # React components
│   │   │   ├── HostList.tsx           # Host reservations table
│   │   │   ├── HostForm.tsx           # Add/edit host form
│   │   │   ├── SubnetList.tsx         # Subnets table
│   │   │   ├── SubnetForm.tsx         # Add/edit subnet form
│   │   │   ├── ZoneList.tsx           # PTR zones table
│   │   │   ├── ZoneForm.tsx           # Add/edit zone form
│   │   │   ├── LeaseList.tsx          # Active/all leases viewer
│   │   │   ├── GlobalConfigForm.tsx   # Global DHCP settings
│   │   │   ├── ConfigViewer.tsx       # Service status and raw config
│   │   │   ├── AppSettingsForm.tsx    # App configuration editor
│   │   │   └── Login.tsx              # Login page
│   │   └── services/
│   │       └── api.tsx        # API service with all endpoints
│   ├── package.json           # Node.js dependencies
│   └── tsconfig.json          # TypeScript configuration
├── deploy.sh                  # Automated deployment script
└── README.md                  # This file
```

## API Endpoints

### Authentication

- `POST /api/auth/login` - Authenticate and receive JWT token
- `POST /api/auth/verify` - Verify token validity
- `POST /api/auth/change-password` - Change password (auto-restarts backend)

### Host Reservations

- `GET /api/hosts` - List all host reservations
- `GET /api/hosts/{hostname}` - Get specific host
- `POST /api/hosts` - Add new host reservation
- `PUT /api/hosts/{hostname}` - Update host
- `DELETE /api/hosts/{hostname}` - Delete host

### Subnets

- `GET /api/subnets` - List all subnets
- `GET /api/subnets/{network}` - Get specific subnet
- `POST /api/subnets` - Add new subnet
- `PUT /api/subnets/{network}` - Update subnet
- `DELETE /api/subnets/{network}` - Delete subnet

### PTR Zones

- `GET /api/zones` - List all zones
- `GET /api/zones/{zone_name}` - Get specific zone
- `POST /api/zones` - Add new zone
- `PUT /api/zones/{zone_name}` - Update zone
- `DELETE /api/zones/{zone_name}` - Delete zone

### Leases

- `GET /api/leases` - Get all leases (active, expired, free)
- `GET /api/leases/active` - Get only active leases

### Global Configuration

- `GET /api/global-config` - Get global DHCP configuration
- `PUT /api/global-config` - Update global configuration

### Service Management

- `GET /api/service/status/{service}` - Get service status (isc-dhcp-server, nginx, dhcp-manager)
- `POST /api/restart/{service}` - Restart service with validation
- `GET /api/config` - Get raw dhcpd.conf content
- `POST /api/validate` - Validate DHCP configuration
- `GET /api/backups` - List configuration backups

### App Configuration

- `GET /api/app-config` - Get app configuration (sensitive values masked)
- `GET /api/app-config/schema` - Get configuration schema
- `PUT /api/app-config` - Update app configuration

### TLS Management

- `GET /api/tls/certificate-info` - Get current certificate information

### System

- `GET /api/system/hostname` - Get server hostname

## Configuration

### Application Configuration File

Located at `/opt/dhcp-manager/config/config.json` (created by deploy.sh)

Key settings:

- `DHCP_CONF_PATH`: Path to dhcpd.conf (default: `/etc/dhcp/dhcpd.conf`)
- `DHCP_LEASES_PATH`: Path to lease file (default: `/var/lib/dhcp/dhcpd.leases`)
- `BACKUP_DIR`: Configuration backup directory (default: `/opt/dhcp-manager/backups`)
- `PASSWORD_FILE`: Bcrypt password hash file (default: `/opt/dhcp-manager/config/password.hash`)
- `TLS_CERT_PATH`: TLS certificate path (default: `/etc/nginx/ssl/dhcp-manager.crt`)
- `TLS_KEY_PATH`: TLS key path (default: `/etc/nginx/ssl/dhcp-manager.key`)
- `LOG_LEVEL`: Application log level (default: `INFO`)

Edit via web interface (App Settings tab) or manually with JSON editor.

### Security Configuration

**Sudo Permissions** (configured in `/etc/sudoers.d/dhcp-manager`):

```bash
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl start isc-dhcp-server
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl stop isc-dhcp-server
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl restart isc-dhcp-server
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl status isc-dhcp-server
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl restart dhcp-manager.service
dhcp-manager ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
dhcp-manager ALL=(ALL) NOPASSWD: /bin/systemctl status nginx
dhcp-manager ALL=(ALL) NOPASSWD: /usr/sbin/dhcpd -t -cf /etc/dhcp/dhcpd.conf
```

**Authentication:**

- JWT tokens with 24-hour expiration
- Bcrypt password hashing with salt
- Automatic logout on 401 responses
- Token stored in browser localStorage

**TLS/HTTPS:**

- Self-signed certificate generated by deploy.sh (10-year validity)
- TLS 1.2 and 1.3 enabled
- Security headers configured in Nginx
- HTTP automatically redirects to HTTPS

## Monitoring and Logs

### Service Logs

```bash
# Backend application logs
sudo journalctl -u dhcp-manager -f

# DHCP server logs
sudo journalctl -u isc-dhcp-server -f

# Nginx access logs
sudo tail -f /var/log/nginx/access.log

# Nginx error logs
sudo tail -f /var/log/nginx/error.log
```

### Service Status

```bash
# Check all services
sudo systemctl status dhcp-manager
sudo systemctl status isc-dhcp-server
sudo systemctl status nginx

# Or view in web interface under "ISC DHCP Service Status" tab
```

## Troubleshooting

### Common Issues

**DHCP Service Won't Start**

- Validate config: `sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf`
- Check logs: `sudo journalctl -u isc-dhcp-server -xe`
- Restore from backup if needed: `/opt/dhcp-manager/backups/`

**Backend Connection Failed**

- Verify service running: `sudo systemctl status dhcp-manager`
- Check port 5000: `sudo ss -tlnp | grep 5000`
- Review backend logs: `sudo journalctl -u dhcp-manager -f`

**401 Unauthorized After Login**

- Password may have changed - use new password
- Token expired - logout and login again
- Check password file: `/opt/dhcp-manager/config/password.hash`

**TLS Certificate Warnings**

- Expected with self-signed certificate
- Click "Advanced" → "Proceed to site" in browser
- Or install custom certificate and update paths in App Settings

**Permission Denied Errors**

- Verify sudo config: `sudo -l -U dhcp-manager`
- Check file ownership: `ls -la /opt/dhcp-manager`
- Ensure dhcp-manager user can read DHCP config and leases

**Service Restart After Password Change**

- Password changes automatically restart backend service
- Wait 5-10 seconds for service to restart
- Refresh page and login with new password

### Validation Errors

Always validate DHCP configuration before restarting:

1. Click "Validate Configuration" button
2. Review any syntax errors
3. Fix errors before restarting service
4. Invalid config will prevent DHCP service from starting

## Production Deployment

### Updates and Upgrades

To update the application:

```bash
cd /path/to/isc-web-dhcp-manager
git pull
sudo ./deploy.sh
```

The deployment script:

- Preserves existing configuration files
- Preserves password hashes
- Keeps backups intact
- Rebuilds frontend
- Restarts services automatically

### Custom TLS Certificates

To use custom certificates:

1. Login to web interface
2. Navigate to App Settings tab
3. Update `TLS_CERT_PATH` and `TLS_KEY_PATH` fields
4. Save settings
5. Restart Nginx from "ISC DHCP Service Status" tab

### Firewall Configuration

Ensure the HTTPS port is accessible. The deployment script uses port 443 by default, or port 8000 if 443 is already in use:

```bash
# UFW (allow both ports to be safe)
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
```

**Note:** Only one port will be used depending on availability. Check deployment output to confirm which port was selected.

## Security Best Practices

1. **Change default password immediately** after deployment
2. **Use custom TLS certificates** for production (not self-signed)
3. **Regularly review backups** in `/opt/dhcp-manager/backups/`
4. **Monitor service logs** for unauthorized access attempts
5. **Keep system updated**: `sudo apt update && sudo apt upgrade`
6. **Restrict network access** to management interface if possible
7. **Review sudo permissions** periodically
8. **Enable firewall** and allow only necessary ports

## Development

### Local Development Workflow

1. Make changes to backend (Python) or frontend (TypeScript/React)
2. Backend auto-reloads in debug mode (`python app.py`)
3. Frontend hot-reloads automatically (`npm start`)
4. Test changes thoroughly before deploying
5. Validate DHCP config changes don't break service

### Adding New Features

1. **Backend**: Add routes in `app.py`, parser logic in `dhcp_parser.py`
2. **Frontend**: Create components in `src/components/`, update API in `src/services/api.tsx`
3. **Validation**: Add validation in both frontend (client-side) and backend (server-side)
4. **Documentation**: Update CLAUDE.md with technical details

### Building for Production

```bash
cd frontend
npm run build
```

Built files output to `frontend/build/` directory

## Architecture

- **Backend**: Flask + Gunicorn WSGI server
- **Frontend**: React SPA with TypeScript
- **Web Server**: Nginx (reverse proxy + TLS termination)
- **Authentication**: JWT tokens with bcrypt password hashing
- **Configuration**: Direct file manipulation with automatic backups
- **Service Management**: systemd with passwordless sudo for specific commands

See `CLAUDE.md` for detailed technical documentation.

## License

This project is developed as a utility tool for managing DHCP configurations. Use at your own discretion and ensure proper backups before making changes to production systems.

## Support

- Review logs: `sudo journalctl -u dhcp-manager -f`
- Check backups: `/opt/dhcp-manager/backups/`
- ISC DHCP documentation: https://www.isc.org/dhcp/
- Configuration schema: `/opt/dhcp-manager/config/config_schema.json`

## Version

**V1.0** - Production ready with complete DHCP management, authentication, TLS support, and automated deployment.
