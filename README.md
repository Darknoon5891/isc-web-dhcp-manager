# ISC Web DHCP Configuration Manager

A web-based interface for managing ISC DHCP Server configuration files. Provides an easy way to manage DHCP host reservations, subnets, DNS zones, and global settings without manually editing the `/etc/dhcp/dhcpd.conf` file.

## Features

- **Host Reservations**: Add, edit, and delete DHCP static host reservations with MAC and IP address bindings
- **Subnet Management**: Configure DHCP subnets with IP ranges, routers, DNS servers, and other options
- **PTR Zone Management**: Configure dynamic DNS reverse zones for automatic PTR record updates
- **Global DHCP Configuration**: Manage lease times, authoritative mode, DDNS settings, NTP servers, and ping checking
- **App Settings Management**: Web-based configuration editor for application settings stored in `/etc/isc-web-dhcp-manager/config.conf`
- **Configuration Validation**: Validate DHCP configuration syntax before applying changes
- **Service Control**: View DHCP service status and restart from the web interface
- **Backup Management**: Automatic backups created before each configuration change
- **Configuration Viewing**: View the raw DHCP configuration file
- **Input Validation**: Client and server-side validation for all configuration parameters

## Quick Start

<b>Built and tested on Debian 12 (amd64) - Using Python 3.11</b>

### Automated Deployment (Recommended for Production)

The easiest way to deploy this application is using the included deployment script:

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd isc-dhcp-rontend
   ```

2. **Run the deployment script:**
   ```bash
   sudo bash deploy.sh
   ```

The deployment script will automatically:

- Install system dependencies (Python 3.11, nginx, isc-dhcp-server)
- Create a dedicated `dhcp-manager` system user
- Set up the backend with gunicorn and systemd service
- Deploy pre-built frontend to nginx
- **Generate self-signed SSL certificate** (10-year validity with FQDN, hostname, and localhost in SAN)
- **Configure nginx with HTTPS** (TLS 1.2/1.3, security headers, HTTP→HTTPS redirect)
- Set up proper file permissions for `/etc/dhcp/dhcpd.conf`
- Create application configuration in `/etc/isc-web-dhcp-manager/`
- Configure sudoers for service management
- **Intelligently detect and configure DHCP**:
  - Preserves existing configs with host declarations
  - Recreates default/invalid configs from fresh ISC DHCP installs
  - Auto-detects network interface and subnet
  - Automatically restarts DHCP service when config is recreated

After deployment completes, the application will be accessible at `https://<your-server-ip>`

**Important Notes:**

- The script expects the application files to be in `/app` directory. Adjust `APP_SOURCE`, `CONFIG_SOURCE`, and `FRONTEND_SOURCE` variables in `deploy.sh` if your path differs.
- Frontend is pre-built and included in the repository - no Node.js required on the server
- The script will auto-detect your network interface and configure DHCP subnet automatically
- DHCP range is set to `.100 - .200` by default (configurable in the script)
- **Self-signed SSL certificate**: Browsers will show security warnings on first access (click "Advanced" → "Proceed")
- Application settings are stored in `/etc/isc-web-dhcp-manager/config.conf` with schema validation
- Configuration schema is located at `/etc/isc-web-dhcp-manager/config_schema.json`
- The script intelligently handles ISC DHCP configuration scenarios:
  - Fresh install with no config → creates new config
  - Fresh install with default config (commented out) → creates new config
  - Existing config with hosts → preserves user configuration
  - Reinstall scenarios → preserves or recreates based on content analysis

### Manual Development Setup

For development and testing purposes:

#### Backend Setup

1. Navigate to the backend directory:

   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the Flask application:
   ```bash
   python app.py
   ```

The backend will start on `http://localhost:5000`.

#### Frontend Setup

1. Navigate to the frontend directory:

   ```bash
   cd frontend
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

The frontend will start on `http://localhost:3000` and automatically proxy API requests to the Flask backend.

## Project Structure

```
isc-dhcp-rontend/
├── backend/
│   ├── app.py              # Main Flask application
│   ├── dhcp_parser.py      # DHCP configuration parser
│   ├── config.py           # Application configuration loader
│   ├── config_manager.py   # App settings manager
│   └── requirements.txt    # Python dependencies
├── config/
│   └── config_schema.json  # Application settings schema (deployed to /etc)
├── frontend/
│   ├── build/              # Pre-built production frontend (for ease of deployment)
│   ├── public/
│   │   └── index.html      # HTML template
│   ├── src/
│   │   ├── App.tsx         # Main React component
│   │   ├── components/     # React components
│   │   │   ├── HostList.tsx
│   │   │   ├── HostForm.tsx
│   │   │   ├── SubnetList.tsx
│   │   │   ├── SubnetForm.tsx
│   │   │   ├── ZoneList.tsx
│   │   │   ├── ZoneForm.tsx
│   │   │   ├── GlobalConfigForm.tsx
│   │   │   ├── AppSettingsForm.tsx
│   │   │   └── ConfigViewer.tsx
│   │   └── services/
│   │       └── api.tsx     # API service layer
│   ├── package.json        # Node.js dependencies
│   └── tsconfig.json       # TypeScript configuration
├── deploy.sh               # Automated deployment script
└── README.md               # This file
```

## Configuration

### Application Configuration

The application uses a configuration file at `/etc/isc-web-dhcp-manager/config.conf`.
All configuration options are validated against the schema in `/etc/isc-web-dhcp-manager/config_schema.json`. You can edit these settings through the "App Settings" tab in the web interface.

### Production Mode (Manual Configuration)

**Note:** For automated deployment, see the "Automated Deployment" section in Quick Start above.

For manual production deployment on a Linux server:

#### 2. File Permissions

The Flask application needs read/write access to the DHCP configuration:

```bash
# Create backup directory
sudo mkdir -p /etc/dhcp/backups

# Set ownership (owner must remain root, change group only)
sudo chown root:dhcp-manager /etc/dhcp/dhcpd.conf
sudo chmod 660 /etc/dhcp/dhcpd.conf

# Allow directory access for temp file creation (atomic writes)
sudo chown root:dhcp-manager /etc/dhcp
sudo chmod 775 /etc/dhcp

# Set backup directory ownership
sudo chown dhcp-manager:dhcp-manager /etc/dhcp/backups
sudo chmod 770 /etc/dhcp/backups
```

#### 3. Sudo Permissions for Service Restart

Create a sudoers file to allow service restarts without password:

```bash
sudo visudo -f /etc/sudoers.d/dhcp-manager
```

Add these lines (replace `flask-user` with your application user):

```
flask-user ALL=(ALL) NOPASSWD: /bin/systemctl restart isc-dhcp-server
flask-user ALL=(ALL) NOPASSWD: /bin/systemctl status isc-dhcp-server
flask-user ALL=(ALL) NOPASSWD: /bin/systemctl is-active isc-dhcp-server
```

Save and set proper permissions:

```bash
sudo chmod 440 /etc/sudoers.d/dhcp-manager
```

#### 4. WSGI Server (Production)

Use Gunicorn instead of Flask development server:

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:create_app()'
```

#### 5. Systemd Service (Optional)

Create `/etc/systemd/system/dhcp-manager.service`:

```ini
[Unit]
Description=ISC Web DHCP Configuration Manager
After=network.target

[Service]
User=flask-user
Group=flask-user
WorkingDirectory=/path/to/isc-dhcp-rontend/backend
Environment="PATH=/path/to/isc-dhcp-rontend/backend/venv/bin"
EnvironmentFile=/path/to/isc-dhcp-rontend/.env
ExecStart=/path/to/isc-dhcp-rontend/backend/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 'app:create_app()'
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dhcp-manager
sudo systemctl start dhcp-manager
```

#### 6. Reverse Proxy (Nginx)

Configure Nginx to proxy requests:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location /api {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        root /path/to/isc-dhcp-rontend/frontend/build;
        try_files $uri /index.html;
    }
}
```

#### 7. Build Frontend for Production

```bash
cd frontend
npm run build
```

The built files will be in `frontend/build/` directory.

## API Endpoints

### Host Reservations

- `GET /api/hosts` - List all host reservations
- `GET /api/hosts/{hostname}` - Get specific host reservation
- `POST /api/hosts` - Add new host reservation
- `PUT /api/hosts/{hostname}` - Update existing host
- `DELETE /api/hosts/{hostname}` - Delete host reservation

### Subnets

- `GET /api/subnets` - List all subnets
- `GET /api/subnets/{network}` - Get specific subnet
- `POST /api/subnets` - Add new subnet
- `PUT /api/subnets/{network}` - Update existing subnet
- `DELETE /api/subnets/{network}` - Delete subnet

### PTR Zones

- `GET /api/zones` - List all PTR zones
- `GET /api/zones/{zone_name}` - Get specific zone
- `POST /api/zones` - Add new zone
- `PUT /api/zones/{zone_name}` - Update existing zone
- `DELETE /api/zones/{zone_name}` - Delete zone

### Global Configuration

- `GET /api/global-config` - Get global DHCP settings
- `PUT /api/global-config` - Update global DHCP settings

### Application Settings

- `GET /api/app-config` - Get application configuration (sensitive values masked)
- `GET /api/app-config/schema` - Get configuration schema
- `PUT /api/app-config` - Update application configuration

### Service Management

- `GET /api/config` - Get raw DHCP configuration content
- `POST /api/validate` - Validate DHCP configuration
- `POST /api/restart` - Restart DHCP service
- `GET /api/service/status` - Get DHCP service status
- `GET /api/backups` - List configuration backups

### System

- `GET /api/system/hostname` - Get server hostname
- `GET /api/` - Health check endpoint

## Security Considerations

- **File Permissions**: Ensure proper access to `/etc/dhcp/dhcpd.conf`
- **Input Validation**: All inputs are validated on both client and server
- **Backups**: Configuration backups are created before each modification
- **Service Control**: Service restart requires appropriate system permissions

## Troubleshooting

### Backend Issues

- Ensure Python 3.8+ is installed
- Check that all dependencies are installed: `pip install -r requirements.txt`
- Verify file permissions for configuration access
- Check Flask application logs for detailed error messages

### Frontend Issues

- Ensure Node.js 16+ is installed
- Clear npm cache: `npm cache clean --force`
- Delete `node_modules` and reinstall: `rm -rf node_modules && npm install`
- Check browser console for JavaScript errors

### DHCP Service Issues

- Validate configuration before restarting service
- Check DHCP service logs: `sudo journalctl -u isc-dhcp-server -f`
- Ensure no syntax errors in configuration file
- Verify network interface configuration

## Development

### Adding New Features

1. Backend changes: Modify `app.py` for new endpoints, `dhcp_parser.py` for config logic
2. Frontend changes: Add components in `src/components/`, update API in `src/services/api.tsx`
3. Update validation rules in both frontend and backend as needed

### Testing

- Backend: Add unit tests for parser logic and API endpoints
- Frontend: Test components with various input combinations
- Integration: Test complete workflows (add/edit/delete hosts)

## License

This project is developed as a utility tool for managing DHCP configurations. Use at your own discretion and ensure proper backups before making changes to production systems.
