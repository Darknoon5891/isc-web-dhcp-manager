/**
 * HostForm Component
 * Form for adding and editing DHCP host reservations
 */

import React, { useState, useEffect } from 'react';
import apiService, { DHCPHost, APIError } from '../services/api';

interface HostFormProps {
  editingHost: DHCPHost | null;
  onSave: () => void;
  onCancel: () => void;
}

const HostForm: React.FC<HostFormProps> = ({ editingHost, onSave, onCancel }) => {
  const [formData, setFormData] = useState({
    hostname: '',
    mac: '',
    ip: ''
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});

  // Initialize form when editing host changes
  useEffect(() => {
    if (editingHost) {
      setFormData({
        hostname: editingHost.hostname,
        mac: editingHost.mac,
        ip: editingHost.ip
      });
    } else {
      setFormData({
        hostname: '',
        mac: '',
        ip: ''
      });
    }
    setErrors({});
  }, [editingHost]);

  const validateForm = (): boolean => {
    const newErrors: { [key: string]: string } = {};

    // Hostname validation
    if (!formData.hostname.trim()) {
      newErrors.hostname = 'Hostname is required';
    } else if (!/^[a-zA-Z0-9-_]+$/.test(formData.hostname)) {
      newErrors.hostname = 'Hostname can only contain letters, numbers, hyphens, and underscores';
    } else if (formData.hostname.length > 63) {
      newErrors.hostname = 'Hostname must be 63 characters or less';
    }

    // MAC address validation
    if (!formData.mac.trim()) {
      newErrors.mac = 'MAC address is required';
    } else if (!/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(formData.mac)) {
      newErrors.mac = 'MAC address must be in format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX';
    }

    // IP address validation
    if (!formData.ip.trim()) {
      newErrors.ip = 'IP address is required';
    } else {
      const ipParts = formData.ip.split('.');
      if (ipParts.length !== 4) {
        newErrors.ip = 'IP address must have 4 octets';
      } else {
        for (const part of ipParts) {
          const num = parseInt(part, 10);
          if (isNaN(num) || num < 0 || num > 255) {
            newErrors.ip = 'Each octet must be between 0 and 255';
            break;
          }
        }
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    
    try {
      const hostData: DHCPHost = {
        hostname: formData.hostname.trim(),
        mac: formatMacAddress(formData.mac.trim()),
        ip: formData.ip.trim()
      };

      if (editingHost) {
        // Update existing host
        await apiService.updateHost(editingHost.hostname, {
          mac: hostData.mac,
          ip: hostData.ip
        });
      } else {
        // Add new host
        await apiService.addHost(hostData);
      }

      onSave();
    } catch (err) {
      if (err instanceof APIError) {
        // Handle specific API errors
        if (err.message.includes('already exists') || err.message.includes('already in use')) {
          if (err.message.includes('MAC')) {
            setErrors({ mac: err.message });
          } else if (err.message.includes('IP')) {
            setErrors({ ip: err.message });
          } else {
            setErrors({ hostname: err.message });
          }
        } else {
          setErrors({ general: err.message });
        }
      } else {
        setErrors({ general: 'An unexpected error occurred. Please try again.' });
      }
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field: keyof typeof formData) => (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    setFormData(prev => ({
      ...prev,
      [field]: e.target.value
    }));
    
    // Clear field-specific error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({
        ...prev,
        [field]: ''
      }));
    }
  };

  const formatMacAddress = (mac: string): string => {
    // Convert to uppercase and ensure colon format
    return mac.toUpperCase().replace(/-/g, ':');
  };

  const handleMacBlur = () => {
    if (formData.mac) {
      setFormData(prev => ({
        ...prev,
        mac: formatMacAddress(prev.mac)
      }));
    }
  };

  return (
    <div className="card">
      <h2>{editingHost ? 'Edit Host Reservation' : 'Add New Host Reservation'}</h2>
      
      {errors.general && (
        <div className="alert alert-error">
          {errors.general}
        </div>
      )}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="hostname">Hostname *</label>
          <input
            type="text"
            id="hostname"
            value={formData.hostname}
            onChange={handleInputChange('hostname')}
            disabled={!!editingHost} // Hostname cannot be changed when editing
            placeholder="e.g., server01, printer-office"
            maxLength={63}
          />
          {errors.hostname && (
            <div style={{ color: '#e74c3c', fontSize: '14px', marginTop: '5px' }}>
              {errors.hostname}
            </div>
          )}
          {editingHost && (
            <div style={{ color: '#666', fontSize: '14px', marginTop: '5px' }}>
              Hostname cannot be changed when editing. Delete and recreate to change hostname.
            </div>
          )}
        </div>

        <div className="form-group">
          <label htmlFor="mac">MAC Address *</label>
          <input
            type="text"
            id="mac"
            value={formData.mac}
            onChange={handleInputChange('mac')}
            onBlur={handleMacBlur}
            placeholder="e.g., 00:11:22:33:44:55"
            style={{ fontFamily: 'monospace' }}
          />
          {errors.mac && (
            <div style={{ color: '#e74c3c', fontSize: '14px', marginTop: '5px' }}>
              {errors.mac}
            </div>
          )}
          <div style={{ color: '#666', fontSize: '14px', marginTop: '5px' }}>
            Format: XX:XX:XX:XX:XX:XX (colons will be added automatically)
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="ip">IP Address *</label>
          <input
            type="text"
            id="ip"
            value={formData.ip}
            onChange={handleInputChange('ip')}
            placeholder="e.g., 192.168.1.100"
            style={{ fontFamily: 'monospace' }}
          />
          {errors.ip && (
            <div style={{ color: '#e74c3c', fontSize: '14px', marginTop: '5px' }}>
              {errors.ip}
            </div>
          )}
        </div>

        <div style={{ marginTop: '20px' }}>
          <button
            type="submit"
            className="btn btn-success"
            disabled={loading}
          >
            {loading ? 'Saving...' : (editingHost ? 'Update Host' : 'Add Host')}
          </button>
          <button
            type="button"
            className="btn"
            onClick={onCancel}
            disabled={loading}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
};

export default HostForm;