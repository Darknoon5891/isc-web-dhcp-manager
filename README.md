# DHCP Configuration Manager

A web-based interface for managing ISC DHCP Server configuration files. Provides an easy way to view, add, edit, and delete DHCP host reservations without manually editing the `/etc/dhcp/dhcpd.conf` file.

## Features

- **Host Management**: Add, edit, and delete DHCP static host reservations
- **Configuration Viewing**: View the raw DHCP configuration file
- **Validation**: Validate configuration before applying changes
- **Service Control**: Restart DHCP service from the web interface
- **Backup Management**: Automatic backups before configuration changes
- **Input Validation**: Client and server-side validation for hostnames, MAC addresses, and IP addresses

## Quick Start

<b>Built and tested on Debian 12 (amd64) - Using Python 3.11</b>

### Clone Repository

```bash
git clone <repository-url>
cd isc-dhcp-rontend
```

### Backend Setup

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

### Frontend Setup

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
dhcp-manager/
├── backend/
│   ├── app.py              # Main Flask application
│   ├── dhcp_parser.py      # DHCP configuration parser
│   ├── config.py           # Application configuration
│   └── requirements.txt    # Python dependencies
├── frontend/
│   ├── public/
│   │   └── index.html      # HTML template
│   ├── src/
│   │   ├── App.tsx         # Main React component
│   │   ├── components/     # React components
│   │   │   ├── HostList.tsx
│   │   │   ├── HostForm.tsx
│   │   │   └── ConfigViewer.tsx
│   │   └── services/
│   │       └── api.tsx     # API service layer
│   ├── package.json        # Node.js dependencies
│   └── tsconfig.json       # TypeScript configuration
├── CLAUDE.md               # Project specifications
└── README.md               # This file
```

## Configuration

### Development Mode

In development mode, the application:

- Uses a test configuration file (`./test_dhcpd.conf`)
- Disables service restart functionality
- Creates automatic backups in `./test_backups/`

### Production Mode

For production deployment on a Linux server:

#### 1. Environment Configuration

Copy the example environment file and configure it:

```bash
cp .env.example .env
nano .env
```

Set the following variables:

- `FLASK_ENV=production`
- `SECRET_KEY` - Generate a secure random key: `python3 -c 'import secrets; print(secrets.token_hex(32))'`
- `CORS_ORIGINS` - Set to your frontend domain(s)
- `DHCP_CONFIG_PATH=/etc/dhcp/dhcpd.conf`
- `DHCP_BACKUP_DIR=/etc/dhcp/backups`

#### 2. File Permissions

The Flask application needs read/write access to the DHCP configuration:

```bash
# Create backup directory
sudo mkdir -p /etc/dhcp/backups

# Set ownership (replace 'flask-user' with your application user)
sudo chown flask-user:flask-user /etc/dhcp/dhcpd.conf
sudo chown flask-user:flask-user /etc/dhcp/backups

# Or use group permissions
sudo chgrp flask-user /etc/dhcp/dhcpd.conf /etc/dhcp/backups
sudo chmod 664 /etc/dhcp/dhcpd.conf
sudo chmod 775 /etc/dhcp/backups
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
Description=DHCP Configuration Manager
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

- `GET /api/hosts` - List all host reservations
- `POST /api/hosts` - Add new host reservation
- `PUT /api/hosts/{hostname}` - Update existing host
- `DELETE /api/hosts/{hostname}` - Delete host reservation
- `GET /api/config` - Get raw configuration content
- `POST /api/validate` - Validate configuration
- `POST /api/restart` - Restart DHCP service
- `GET /api/service/status` - Get service status
- `GET /api/backups` - List configuration backups

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
