/**
 * SubnetForm Component
 * Form for adding and editing DHCP subnet declarations
 */

import React, { useState, useEffect } from 'react';
import apiService, { DHCPSubnet, APIError } from '../services/api';

interface SubnetFormProps {
  editingSubnet: DHCPSubnet | null;
  onSave: () => void;
  onCancel: () => void;
}

const SubnetForm: React.FC<SubnetFormProps> = ({ editingSubnet, onSave, onCancel }) => {
  const [formData, setFormData] = useState({
    network: '',
    netmask: '255.255.255.0',
    range_start: '',
    range_end: '',
    routers: '',
    subnetMask: '',
    broadcastAddress: '',
    domainNameServers: ''
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [createPtrZone, setCreatePtrZone] = useState(false);
  const [ptrPrimaryDns, setPtrPrimaryDns] = useState('');

  // Initialize form when editing subnet changes
  useEffect(() => {
    if (editingSubnet) {
      setFormData({
        network: editingSubnet.network,
        netmask: editingSubnet.netmask,
        range_start: editingSubnet.range_start || '',
        range_end: editingSubnet.range_end || '',
        routers: editingSubnet.options?.['routers'] || '',
        subnetMask: editingSubnet.options?.['subnet-mask'] || '',
        broadcastAddress: editingSubnet.options?.['broadcast-address'] || '',
        domainNameServers: editingSubnet.options?.['domain-name-servers'] || ''
      });
    } else {
      setFormData({
        network: '',
        netmask: '255.255.255.0',
        range_start: '',
        range_end: '',
        routers: '',
        subnetMask: '',
        broadcastAddress: '',
        domainNameServers: ''
      });
    }
    setErrors({});
    setCreatePtrZone(false);
    setPtrPrimaryDns('');
  }, [editingSubnet]);

  const generateReverseZoneFromSubnet = (network: string): string => {
    // Convert network address to reverse zone name (e.g., 192.168.1.0 -> 1.168.192.in-addr.arpa)
    const parts = network.split('.');
    if (parts.length < 3) {
      return '';
    }
    return `${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
  };

  const validateIP = (ip: string): boolean => {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
      const num = parseInt(part, 10);
      return !isNaN(num) && num >= 0 && num <= 255;
    });
  };

  const validateForm = (): boolean => {
    const newErrors: { [key: string]: string } = {};

    // Network validation
    if (!formData.network.trim()) {
      newErrors.network = 'Network address is required';
    } else if (!validateIP(formData.network)) {
      newErrors.network = 'Invalid network address format';
    }

    // Netmask validation
    if (!formData.netmask.trim()) {
      newErrors.netmask = 'Netmask is required';
    } else if (!validateIP(formData.netmask)) {
      newErrors.netmask = 'Invalid netmask format';
    }

    // Range validation (optional but both required if one is set)
    if (formData.range_start || formData.range_end) {
      if (!formData.range_start) {
        newErrors.range_start = 'Range start is required when range end is set';
      } else if (!validateIP(formData.range_start)) {
        newErrors.range_start = 'Invalid IP address format';
      }

      if (!formData.range_end) {
        newErrors.range_end = 'Range end is required when range start is set';
      } else if (!validateIP(formData.range_end)) {
        newErrors.range_end = 'Invalid IP address format';
      }
    }

    // Optional field validations
    if (formData.routers && !validateIP(formData.routers)) {
      newErrors.routers = 'Invalid router IP address';
    }

    if (formData.subnetMask && !validateIP(formData.subnetMask)) {
      newErrors.subnetMask = 'Invalid subnet mask';
    }

    if (formData.broadcastAddress && !validateIP(formData.broadcastAddress)) {
      newErrors.broadcastAddress = 'Invalid broadcast address';
    }

    if (formData.domainNameServers) {
      const dnsServers = formData.domainNameServers.split(',').map(s => s.trim());
      for (const dns of dnsServers) {
        if (!validateIP(dns)) {
          newErrors.domainNameServers = 'Invalid DNS server address format (use comma-separated IPs)';
          break;
        }
      }
    }

    // PTR zone validation
    if (createPtrZone && !editingSubnet) {
      if (!ptrPrimaryDns.trim()) {
        newErrors.ptrPrimaryDns = 'Primary DNS server is required for PTR zone creation';
      } else if (!validateIP(ptrPrimaryDns)) {
        newErrors.ptrPrimaryDns = 'Invalid primary DNS server IP address';
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

      // Build options object
      const options: { [key: string]: string } = {};
      if (formData.routers) options['routers'] = formData.routers;
      if (formData.subnetMask) options['subnet-mask'] = formData.subnetMask;
      if (formData.broadcastAddress) options['broadcast-address'] = formData.broadcastAddress;
      if (formData.domainNameServers) options['domain-name-servers'] = formData.domainNameServers;

      const subnetData: DHCPSubnet = {
        network: formData.network,
        netmask: formData.netmask,
        range_start: formData.range_start || undefined,
        range_end: formData.range_end || undefined,
        options: Object.keys(options).length > 0 ? options : undefined
      };

      if (editingSubnet) {
        // Update existing subnet
        const { network, ...updates } = subnetData;
        await apiService.updateSubnet(editingSubnet.network, updates);
      } else {
        // Add new subnet
        await apiService.addSubnet(subnetData);

        // Create PTR zone if requested
        if (createPtrZone && ptrPrimaryDns) {
          try {
            const reverseZoneName = generateReverseZoneFromSubnet(formData.network);
            if (reverseZoneName) {
              await apiService.addZone({
                zone_name: reverseZoneName,
                primary: ptrPrimaryDns
              });
            }
          } catch (zoneErr) {
            // Don't fail the entire operation if zone creation fails
            const reverseZoneName = generateReverseZoneFromSubnet(formData.network);
            if (zoneErr instanceof APIError) {
              setErrors({ submit: `Subnet created successfully, but PTR zone creation failed: ${zoneErr.message}. You can manually create zone "${reverseZoneName}" in the PTR Zones tab.` });
              setLoading(false);
              return;
            } else {
              setErrors({ submit: `Subnet created successfully, but PTR zone "${reverseZoneName}" creation failed. You can manually create it in the PTR Zones tab.` });
              setLoading(false);
              return;
            }
          }
        }
      }

      onSave();
    } catch (err) {
      if (err instanceof APIError) {
        setErrors({ submit: err.message });
      } else {
        setErrors({ submit: 'Failed to save subnet. Please try again.' });
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
      <h2>{editingSubnet ? 'Edit Subnet' : 'Add New Subnet'}</h2>

      <form onSubmit={handleSubmit}>
        {errors.submit && (
          <div className="alert alert-error" style={{ marginBottom: '20px' }}>
            {errors.submit}
          </div>
        )}

        <div className="form-group">
          <label htmlFor="network">
            Network Address <span style={{ color: '#e74c3c' }}>*</span>
          </label>
          <input
            id="network"
            type="text"
            value={formData.network}
            onChange={(e) => handleChange('network', e.target.value)}
            placeholder="192.168.1.0"
            disabled={!!editingSubnet}
            className={errors.network ? 'error' : ''}
          />
          {errors.network && <span className="error-message">{errors.network}</span>}
          {editingSubnet && (
            <small style={{ color: '#666' }}>Network address cannot be changed</small>
          )}
        </div>

        <div className="form-group">
          <label htmlFor="netmask">
            Netmask <span style={{ color: '#e74c3c' }}>*</span>
          </label>
          <select
            id="netmask"
            value={formData.netmask}
            onChange={(e) => handleChange('netmask', e.target.value)}
            className={errors.netmask ? 'error' : ''}
          >
            <option value="255.255.255.0">/24 - 255.255.255.0</option>
            <option value="255.255.255.128">/25 - 255.255.255.128</option>
            <option value="255.255.255.192">/26 - 255.255.255.192</option>
            <option value="255.255.255.224">/27 - 255.255.255.224</option>
            <option value="255.255.254.0">/23 - 255.255.254.0</option>
            <option value="255.255.252.0">/22 - 255.255.252.0</option>
            <option value="255.255.248.0">/21 - 255.255.248.0</option>
            <option value="255.255.240.0">/20 - 255.255.240.0</option>
            <option value="255.255.0.0">/16 - 255.255.0.0</option>
            <option value="255.0.0.0">/8 - 255.0.0.0</option>
          </select>
          {errors.netmask && <span className="error-message">{errors.netmask}</span>}
        </div>

        <div className="form-group">
          <label htmlFor="range_start">DHCP Range Start</label>
          <input
            id="range_start"
            type="text"
            value={formData.range_start}
            onChange={(e) => handleChange('range_start', e.target.value)}
            placeholder="192.168.1.100"
            className={errors.range_start ? 'error' : ''}
          />
          {errors.range_start && <span className="error-message">{errors.range_start}</span>}
        </div>

        <div className="form-group">
          <label htmlFor="range_end">DHCP Range End</label>
          <input
            id="range_end"
            type="text"
            value={formData.range_end}
            onChange={(e) => handleChange('range_end', e.target.value)}
            placeholder="192.168.1.200"
            className={errors.range_end ? 'error' : ''}
          />
          {errors.range_end && <span className="error-message">{errors.range_end}</span>}
        </div>

        <h3 style={{ marginTop: '30px', marginBottom: '15px', fontSize: '18px' }}>Options (Optional)</h3>

        <div className="form-group">
          <label htmlFor="routers">Router (Gateway)</label>
          <input
            id="routers"
            type="text"
            value={formData.routers}
            onChange={(e) => handleChange('routers', e.target.value)}
            placeholder="192.168.1.1"
            className={errors.routers ? 'error' : ''}
          />
          {errors.routers && <span className="error-message">{errors.routers}</span>}
        </div>

        <div className="form-group">
          <label htmlFor="subnetMask">Subnet Mask Option</label>
          <input
            id="subnetMask"
            type="text"
            value={formData.subnetMask}
            onChange={(e) => handleChange('subnetMask', e.target.value)}
            placeholder="255.255.255.0"
            className={errors.subnetMask ? 'error' : ''}
          />
          {errors.subnetMask && <span className="error-message">{errors.subnetMask}</span>}
        </div>

        <div className="form-group">
          <label htmlFor="broadcastAddress">Broadcast Address</label>
          <input
            id="broadcastAddress"
            type="text"
            value={formData.broadcastAddress}
            onChange={(e) => handleChange('broadcastAddress', e.target.value)}
            placeholder="192.168.1.255"
            className={errors.broadcastAddress ? 'error' : ''}
          />
          {errors.broadcastAddress && <span className="error-message">{errors.broadcastAddress}</span>}
        </div>

        <div className="form-group">
          <label htmlFor="domainNameServers">DNS Servers (comma-separated)</label>
          <input
            id="domainNameServers"
            type="text"
            value={formData.domainNameServers}
            onChange={(e) => handleChange('domainNameServers', e.target.value)}
            placeholder="8.8.8.8, 8.8.4.4"
            className={errors.domainNameServers ? 'error' : ''}
          />
          {errors.domainNameServers && <span className="error-message">{errors.domainNameServers}</span>}
        </div>

        {/* PTR Zone Auto-Creation Section */}
        {!editingSubnet && (
          <div style={{
            backgroundColor: '#e3f2fd',
            padding: '20px',
            borderRadius: '4px',
            marginTop: '30px',
            border: '1px solid #90caf9'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '15px' }}>
              <input
                id="createPtrZone"
                type="checkbox"
                checked={createPtrZone}
                onChange={(e) => setCreatePtrZone(e.target.checked)}
                style={{ marginRight: '10px', width: 'auto' }}
              />
              <label htmlFor="createPtrZone" style={{ fontWeight: 'bold', margin: 0, cursor: 'pointer' }}>
                Auto-create PTR Zone for this subnet
              </label>
            </div>

            {createPtrZone && (
              <div className="form-group" style={{ marginBottom: '10px' }}>
                <label htmlFor="ptrPrimaryDns">
                  Primary DNS Server for PTR Zone <span style={{ color: '#e74c3c' }}>*</span>
                </label>
                <input
                  id="ptrPrimaryDns"
                  type="text"
                  value={ptrPrimaryDns}
                  onChange={(e) => {
                    setPtrPrimaryDns(e.target.value);
                    if (errors.ptrPrimaryDns) {
                      setErrors({ ...errors, ptrPrimaryDns: '' });
                    }
                  }}
                  placeholder="192.168.1.1"
                  className={errors.ptrPrimaryDns ? 'error' : ''}
                />
                {errors.ptrPrimaryDns && <span className="error-message">{errors.ptrPrimaryDns}</span>}
                <small style={{ color: '#1565c0', display: 'block', marginTop: '5px' }}>
                  This will create a reverse DNS zone: <strong>{formData.network ? generateReverseZoneFromSubnet(formData.network) : '(enter network first)'}</strong>
                </small>
              </div>
            )}

            <small style={{ color: '#1565c0', display: 'block' }}>
              {createPtrZone
                ? 'A PTR zone will be automatically created for reverse DNS lookups when you save this subnet.'
                : 'Enable this option to automatically create a corresponding PTR zone for reverse DNS lookups.'
              }
            </small>
          </div>
        )}

        <div className="form-actions" style={{ marginTop: '30px', display: 'flex', gap: '10px' }}>
          <button type="submit" className="btn btn-success" disabled={loading}>
            {loading ? (createPtrZone && !editingSubnet ? 'Saving subnet and creating PTR zone...' : 'Saving...') : editingSubnet ? 'Update Subnet' : 'Add Subnet'}
          </button>
          <button type="button" className="btn" onClick={onCancel} disabled={loading}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
};

export default SubnetForm;
