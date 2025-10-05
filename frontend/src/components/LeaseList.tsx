/**
 * LeaseList Component
 * Displays a table of DHCP leases with search and filter functionality
 */

import React, { useState, useEffect } from 'react';
import apiService, { DHCPLease, APIError } from '../services/api';

interface LeaseListProps {
  refreshTrigger: number;
}

const LeaseList: React.FC<LeaseListProps> = ({ refreshTrigger }) => {
  const [leases, setLeases] = useState<DHCPLease[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showActiveOnly, setShowActiveOnly] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const loadLeases = async () => {
    try {
      setLoading(true);
      setError(null);
      const leaseData = showActiveOnly
        ? await apiService.getActiveLeases()
        : await apiService.getLeases();
      setLeases(leaseData);
    } catch (err) {
      if (err instanceof APIError) {
        setError(`Failed to load leases: ${err.message}`);
      } else {
        setError('Failed to load leases. Please check your connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLeases();
  }, [refreshTrigger, showActiveOnly]);

  // Auto-refresh effect
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadLeases();
    }, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, [autoRefresh, showActiveOnly]);

  const handleRefresh = () => {
    loadLeases();
  };

  const formatDateTime = (dateTimeStr: string): string => {
    if (!dateTimeStr || dateTimeStr === 'unknown') {
      return 'Unknown';
    }

    try {
      // ISC DHCP format: YYYY/MM/DD HH:MM:SS
      const [datePart, timePart] = dateTimeStr.split(' ');
      const [year, month, day] = datePart.split('/');
      const dateObj = new Date(`${year}-${month}-${day}T${timePart}`);

      return dateObj.toLocaleString();
    } catch {
      return dateTimeStr;
    }
  };

  const getStateColor = (state: string): string => {
    switch (state) {
      case 'active':
        return '#27ae60';
      case 'expired':
        return '#e74c3c';
      case 'free':
        return '#95a5a6';
      default:
        return '#f39c12';
    }
  };

  const getStateLabel = (state: string): string => {
    return state.charAt(0).toUpperCase() + state.slice(1);
  };

  const filteredLeases = leases.filter((lease) => {
    const searchLower = searchTerm.toLowerCase();
    return (
      lease.ip.toLowerCase().includes(searchLower) ||
      lease.mac.toLowerCase().includes(searchLower) ||
      (lease.hostname && lease.hostname.toLowerCase().includes(searchLower)) ||
      lease.state.toLowerCase().includes(searchLower)
    );
  });

  if (loading) {
    return (
      <div className="card">
        <div className="loading">Loading leases...</div>
      </div>
    );
  }

  return (
    <div>
      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        <div style={{ marginBottom: '20px', display: 'flex', gap: '15px', alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Search leases..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              flex: '1',
              minWidth: '200px',
              padding: '10px',
              fontSize: '14px',
              border: '1px solid #ddd',
              borderRadius: '4px',
            }}
          />

          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={showActiveOnly}
              onChange={(e) => setShowActiveOnly(e.target.checked)}
            />
            <span>Active only</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span>Auto-refresh (30s)</span>
          </label>

          <button
            className="btn"
            onClick={handleRefresh}
            disabled={loading}
            style={{ background: '#3498db' }}
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {filteredLeases.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
            <p>No leases found.</p>
            {searchTerm && <p style={{ fontSize: '14px' }}>Try adjusting your search criteria.</p>}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>MAC Address</th>
                  <th>Hostname</th>
                  <th>Start Time</th>
                  <th>End Time</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {filteredLeases.map((lease, index) => (
                  <tr key={`${lease.ip}-${index}`}>
                    <td>
                      <code>{lease.ip}</code>
                    </td>
                    <td>
                      <code>{lease.mac}</code>
                    </td>
                    <td>{lease.hostname || <em style={{ color: '#999' }}>-</em>}</td>
                    <td style={{ fontSize: '13px' }}>{formatDateTime(lease.starts)}</td>
                    <td style={{ fontSize: '13px' }}>{formatDateTime(lease.ends)}</td>
                    <td>
                      <span
                        style={{
                          padding: '4px 8px',
                          borderRadius: '4px',
                          fontSize: '12px',
                          fontWeight: 'bold',
                          color: 'white',
                          backgroundColor: getStateColor(lease.state),
                        }}
                      >
                        {getStateLabel(lease.state)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div style={{ marginTop: '20px', fontSize: '14px', color: '#666' }}>
          Showing {filteredLeases.length} of {leases.length} lease{leases.length !== 1 ? 's' : ''}
          {searchTerm && ` matching "${searchTerm}"`}
        </div>
      </div>
    </div>
  );
};

export default LeaseList;
