"""
Configuration Manager for ISC Web DHCP Manager
Handles reading, writing, and validating application configuration
Uses /etc/isc-web-dhcp-manager/config_schema.json for field definitions
"""

import os
import json
import tempfile
from typing import Dict, List, Any, Tuple


class ConfigManager:
    """Manages application configuration file"""

    def __init__(self,
                 config_path='/etc/isc-web-dhcp-manager/config.conf',
                 schema_path=None):
        self.config_path = config_path

        # Default schema path is in /etc alongside config file
        if schema_path is None:
            schema_path = '/etc/isc-web-dhcp-manager/config_schema.json'

        self.schema_path = schema_path
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict[str, Any]:
        """Load configuration schema from JSON file"""
        try:
            with open(self.schema_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Schema file not found: {self.schema_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid schema JSON: {e}")

    def read_config(self) -> Dict[str, str]:
        """Read configuration file and return as dictionary"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        config = {}

        try:
            with open(self.config_path, 'r') as f:
                for line in f:
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse KEY=VALUE
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        if key:
                            config[key] = value

            return config

        except Exception as e:
            raise IOError(f"Failed to read config file: {str(e)}")

    def write_config(self, config: Dict[str, str]) -> None:
        """Write configuration to file atomically"""
        try:
            # Validate before writing
            errors = self.validate_config(config)
            if errors:
                raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")

            # Create temporary file in same directory
            config_dir = os.path.dirname(self.config_path)
            config_file = os.path.basename(self.config_path)

            fd, temp_path = tempfile.mkstemp(
                dir=config_dir,
                prefix=f'.{config_file}.',
                suffix='.tmp',
                text=True
            )

            try:
                # Get sections from schema
                sections = {}
                for key, props in self.schema.get('properties', {}).items():
                    section = props.get('section', 'Other')
                    order = props.get('order', 999)
                    if section not in sections:
                        sections[section] = []
                    sections[section].append((order, key, props))

                # Sort sections by first item's order
                sorted_sections = sorted(sections.items(), key=lambda x: min(item[0] for item in x[1]))

                # Write configuration with comments
                with os.fdopen(fd, 'w') as f:
                    f.write("# ISC Web DHCP Manager Configuration\n")
                    f.write("#\n")
                    f.write("# IMPORTANT: When adding new configuration options, update the schema file:\n")
                    f.write("# /etc/isc-web-dhcp-manager/config_schema.json\n")

                    for section_name, items in sorted_sections:
                        f.write(f"\n# {section_name}\n")

                        # Sort items within section by order
                        sorted_items = sorted(items, key=lambda x: x[0])

                        for order, key, props in sorted_items:
                            if key in config:
                                # Add description as comment
                                description = props.get('description', '')
                                if description:
                                    f.write(f"# {description}\n")

                                f.write(f"{key}={config[key]}\n")

                    # Sync to disk
                    f.flush()
                    os.fsync(f.fileno())

                # Preserve permissions
                if os.path.exists(self.config_path):
                    stat_info = os.stat(self.config_path)
                    os.chmod(temp_path, stat_info.st_mode)
                    try:
                        os.chown(temp_path, stat_info.st_uid, stat_info.st_gid)
                    except (PermissionError, OSError):
                        pass

                # Atomic rename
                os.replace(temp_path, self.config_path)

            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
                raise

        except PermissionError:
            raise PermissionError(f"Permission denied writing to {self.config_path}")
        except Exception as e:
            raise IOError(f"Failed to write config file: {str(e)}")

    def validate_config(self, config: Dict[str, str]) -> List[str]:
        """Validate configuration against schema, return list of errors"""
        errors = []
        properties = self.schema.get('properties', {})
        required = self.schema.get('required', [])

        # Check required fields
        for key in required:
            if key not in config or not config[key]:
                errors.append(f"{key} is required")

        # Validate each field
        for key, value in config.items():
            if key not in properties:
                # Unknown field - warning but not error
                continue

            props = properties[key]
            field_type = props.get('type')

            # Type validation
            if field_type == 'integer':
                try:
                    int_val = int(value)

                    # Check minimum
                    if 'minimum' in props and int_val < props['minimum']:
                        errors.append(f"{key} must be at least {props['minimum']}")

                    # Check maximum
                    if 'maximum' in props and int_val > props['maximum']:
                        errors.append(f"{key} must be at most {props['maximum']}")

                except ValueError:
                    errors.append(f"{key} must be an integer")

            elif field_type == 'boolean':
                if value.lower() not in ['true', 'false']:
                    errors.append(f"{key} must be 'true' or 'false'")

            elif field_type == 'string':
                # Check format
                if props.get('format') == 'path':
                    if not value.startswith('/'):
                        errors.append(f"{key} must be an absolute path (start with /)")

                # Check enum
                if 'enum' in props:
                    if value not in props['enum']:
                        valid_values = ', '.join(props['enum'])
                        errors.append(f"{key} must be one of: {valid_values}")

        return errors

    def get_schema(self) -> Dict[str, Any]:
        """Get configuration schema for frontend"""
        return self.schema

    def mask_sensitive_values(self, config: Dict[str, str]) -> Dict[str, str]:
        """Mask sensitive configuration values for display"""
        masked = config.copy()
        properties = self.schema.get('properties', {})

        for key, props in properties.items():
            if props.get('sensitive') and key in masked:
                # Show first 8 chars, mask the rest
                value = masked[key]
                if len(value) > 8:
                    masked[key] = value[:8] + '*' * (len(value) - 8)
                else:
                    masked[key] = '*' * len(value)

        return masked
