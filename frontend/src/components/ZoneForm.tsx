/**
 * ZoneForm Component
 * Form for adding and editing DHCP zone declarations (PTR records)
 */

import React, { useState, useEffect } from 'react';
import apiService, { DHCPZone, APIError } from '../services/api';

interface ZoneFormProps {
  editingZone: DHCPZone | null;
  onSave: () => void;
  onCancel: () => void;
}

const ZoneForm: React.FC<ZoneFormProps> = ({ editingZone, onSave, onCancel }) => {
  const [formData, setFormData] = useState({
    zone_name: '',
    primary: '',
    key_name: '',
    secondary: ''
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [helperNetwork, setHelperNetwork] = useState('');

  // Initialize form when editing zone changes
  useEffect(() => {
    if (editingZone) {
      setFormData({
        zone_name: editingZone.zone_name,
        primary: editingZone.primary,
        key_name: editingZone.key_name || '',
        secondary: editingZone.secondary?.join(', ') || ''
      });
    } else {
      setFormData({
        zone_name: '',
        primary: '',
        key_name: '',
        secondary: ''
      });
    }
    setErrors({});
    setHelperNetwork('');
  }, [editingZone]);

  const validateIP = (ip: string): boolean => {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
      const num = parseInt(part, 10);
      return !isNaN(num) && num >= 0 && num <= 255;
    });
  };

  const generateReverseZone = () => {
    if (!helperNetwork) {
      setErrors({ ...errors, zone_name: 'Enter a network address in the helper field first' });
      return;
    }

    const parts = helperNetwork.split('.');
    if (parts.length < 3) {
      setErrors({ ...errors, zone_name: 'Invalid network format. Use format: 192.168.1.0' });
      return;
    }

    // For /24 networks, reverse first 3 octets
    const reversed = `${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
    setFormData({ ...formData, zone_name: reversed });
    setErrors({ ...errors, zone_name: '' });
  };

  const validateForm = (): boolean => {
    const newErrors: { [key: string]: string } = {};

    // Zone name validation
    if (!formData.zone_name.trim()) {
      newErrors.zone_name = 'Zone name is required';
    } else if (formData.zone_name.length < 3) {
      newErrors.zone_name = 'Zone name too short';
    }

    // Primary DNS validation
    if (!formData.primary.trim()) {
      newErrors.primary = 'Primary DNS server is required';
    } else if (!validateIP(formData.primary)) {
      newErrors.primary = 'Invalid primary DNS server IP address';
    }

    // Secondary DNS validation (optional, comma-separated)
    if (formData.secondary) {
      const secondaryServers = formData.secondary.split(',').map(s => s.trim()).filter(s => s);
      for (const sec of secondaryServers) {
        if (!validateIP(sec)) {
          newErrors.secondary = 'Invalid secondary DNS server IP (use comma-separated IPs)';
          break;
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

    try {
      setLoading(true);

      // Parse secondary servers
      const secondaryList = formData.secondary
        ? formData.secondary.split(',').map(s => s.trim()).filter(s => s)
        : [];

      const zoneData: DHCPZone = {
        zone_name: formData.zone_name,
        primary: formData.primary,
        key_name: formData.key_name || undefined,
        secondary: secondaryList.length > 0 ? secondaryList : undefined
      };

      if (editingZone) {
        // Update existing zone
        const { zone_name, ...updates } = zoneData;
        await apiService.updateZone(editingZone.zone_name, updates);
      } else {
        // Add new zone
        await apiService.addZone(zoneData);
      }

      onSave();
    } catch (err) {
      if (err instanceof APIError) {
        setErrors({ submit: err.message });
      } else {
        setErrors({ submit: 'Failed to save zone. Please try again.' });
      }
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (field: string, value: string) => {
    setFormData({ ...formData, [field]: value });
    // Clear error for this field when user starts typing
    if (errors[field]) {
      setErrors({ ...errors, [field]: '' });
    }
  };

  return (
    <div className="card">
      <h2>{editingZone ? 'Edit DNS Zone' : 'Add New DNS Zone'}</h2>

      <form onSubmit={handleSubmit}>
        {errors.submit && (
          <div className="alert alert-error" style={{ marginBottom: '20px' }}>
            {errors.submit}
          </div>
        )}

        <div className="form-group">
          <label htmlFor="zone_name">
            Zone Name <span style={{ color: '#e74c3c' }}>*</span>
          </label>
          <input
            id="zone_name"
            type="text"
            value={formData.zone_name}
            onChange={(e) => handleChange('zone_name', e.target.value)}
            placeholder="1.168.192.in-addr.arpa"
            disabled={!!editingZone}
            className={errors.zone_name ? 'error' : ''}
          />
          {errors.zone_name && <span className="error-message">{errors.zone_name}</span>}
          {editingZone && (
            <small style={{ color: 'var(--text-muted)', transition: 'color 0.3s' }}>Zone name cannot be changed</small>
          )}
        </div>

        {!editingZone && (
          <div className="form-group" style={{
            backgroundColor: 'var(--bg-helper-section)',
            padding: '15px',
            borderRadius: '4px',
            marginBottom: '20px',
            transition: 'background-color 0.3s',
          }}>
            <label htmlFor="helper" style={{ fontWeight: 'normal' }}>
              <strong>Helper:</strong> Generate reverse zone from network
            </label>
            <div style={{ display: 'flex', gap: '10px', marginTop: '8px' }}>
              <input
                id="helper"
                type="text"
                value={helperNetwork}
                onChange={(e) => setHelperNetwork(e.target.value)}
                placeholder="192.168.1.0"
                style={{ flex: 1 }}
              />
              <button
                type="button"
                className="btn"
                onClick={generateReverseZone}
              >
                Generate Zone Name
              </button>
            </div>
            <small style={{ color: '#666', marginTop: '5px', display: 'block' }}>
              Enter a network address (e.g., 192.168.1.0) to auto-generate the reverse zone name
            </small>
          </div>
        )}

        <div className="form-group">
          <label htmlFor="primary">
            Primary DNS Server <span style={{ color: '#e74c3c' }}>*</span>
          </label>
          <input
            id="primary"
            type="text"
            value={formData.primary}
            onChange={(e) => handleChange('primary', e.target.value)}
            placeholder="192.168.1.1"
            className={errors.primary ? 'error' : ''}
          />
          {errors.primary && <span className="error-message">{errors.primary}</span>}
          <small style={{ color: '#666' }}>IP address of the primary DNS server for updates</small>
        </div>

        <h3 style={{ marginTop: '30px', marginBottom: '15px', fontSize: '18px' }}>Authentication & Secondary (Optional)</h3>

        <div className="form-group">
          <label htmlFor="key_name">TSIG Key Name</label>
          <input
            id="key_name"
            type="text"
            value={formData.key_name}
            onChange={(e) => handleChange('key_name', e.target.value)}
            placeholder="update-key"
            className={errors.key_name ? 'error' : ''}
          />
          {errors.key_name && <span className="error-message">{errors.key_name}</span>}
          <small style={{ color: '#666' }}>TSIG key name for authenticated DNS updates (must be configured in DNS server)</small>
        </div>

        <div className="form-group">
          <label htmlFor="secondary">Secondary DNS Servers (comma-separated)</label>
          <input
            id="secondary"
            type="text"
            value={formData.secondary}
            onChange={(e) => handleChange('secondary', e.target.value)}
            placeholder="192.168.1.2, 192.168.1.3"
            className={errors.secondary ? 'error' : ''}
          />
          {errors.secondary && <span className="error-message">{errors.secondary}</span>}
          <small style={{ color: '#666' }}>Additional DNS servers to notify of updates</small>
        </div>

        <div className="form-actions" style={{ marginTop: '30px', display: 'flex', gap: '10px' }}>
          <button type="submit" className="btn btn-success" disabled={loading}>
            {loading ? 'Saving...' : editingZone ? 'Update Zone' : 'Add Zone'}
          </button>
          <button type="button" className="btn" onClick={onCancel} disabled={loading}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
};

export default ZoneForm;
