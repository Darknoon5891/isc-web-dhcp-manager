/**
 * HostList Component
 * Displays a table of DHCP host reservations with edit/delete functionality
 */

import React, { useState, useEffect } from 'react';
import apiService, { DHCPHost, APIError } from '../services/api';

interface HostListProps {
  onEditHost: (host: DHCPHost) => void;
  onRefresh: () => void;
  refreshTrigger: number;
}

const HostList: React.FC<HostListProps> = ({ onEditHost, onRefresh, refreshTrigger }) => {
  const [hosts, setHosts] = useState<DHCPHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [deleteLoading, setDeleteLoading] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ hostname: string } | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const loadHosts = async () => {
    try {
      setLoading(true);
      setError(null);
      const hostData = await apiService.getHosts();
      setHosts(hostData);
    } catch (err) {
      if (err instanceof APIError) {
        setError(`Failed to load hosts: ${err.message}`);
      } else {
        setError('Failed to load hosts. Please check your connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHosts();
  }, [refreshTrigger]);

  const handleDeleteClick = (hostname: string) => {
    setConfirmDelete({ hostname });
    setDeleteError(null);
  };

  const handleCancelDelete = () => {
    setConfirmDelete(null);
    setDeleteError(null);
  };

  const handleConfirmDelete = async () => {
    if (!confirmDelete) return;

    const hostname = confirmDelete.hostname;

    try {
      setDeleteLoading(hostname);
      setDeleteError(null);
      await apiService.deleteHost(hostname);
      await loadHosts(); // Refresh the list
      onRefresh(); // Trigger any parent refresh
      setConfirmDelete(null);
    } catch (err) {
      if (err instanceof APIError) {
        setDeleteError(`Failed to delete host: ${err.message}`);
      } else {
        setDeleteError('Failed to delete host. Please try again.');
      }
    } finally {
      setDeleteLoading(null);
    }
  };

  const handleEdit = (host: DHCPHost) => {
    onEditHost(host);
  };

  // Filter hosts based on search term
  const filteredHosts = hosts.filter(host =>
    host.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
    host.mac.toLowerCase().includes(searchTerm.toLowerCase()) ||
    host.ip.includes(searchTerm)
  );

  const formatMacAddress = (mac: string) => {
    // Ensure consistent MAC address formatting
    return mac.toUpperCase();
  };

  if (loading) {
    return (
      <div className="card">
        <div className="loading">Loading host reservations...</div>
      </div>
    );
  }

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>DHCP Host Reservations</h2>
        <button 
          className="btn" 
          onClick={loadHosts}
          disabled={loading}
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="alert alert-error">
          {error}
        </div>
      )}

      <div className="form-group" style={{ marginBottom: '20px' }}>
        <input
          type="text"
          placeholder="Search hosts by hostname, MAC address, or IP..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ maxWidth: '400px' }}
        />
      </div>

      {hosts.length === 0 && !loading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
          <p>No DHCP host reservations found.</p>
          <p>Click "Add Host" to create your first reservation.</p>
        </div>
      ) : (
        <>
          <div style={{ marginBottom: '10px', color: '#666' }}>
            Showing {filteredHosts.length} of {hosts.length} hosts
          </div>
          
          <div style={{ overflowX: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>MAC Address</th>
                  <th>IP Address</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredHosts.map((host) => (
                  <tr key={host.hostname}>
                    <td>
                      <strong>{host.hostname}</strong>
                    </td>
                    <td>
                      <code>{formatMacAddress(host.mac)}</code>
                    </td>
                    <td>
                      <code>{host.ip}</code>
                    </td>
                    <td>
                      <button
                        className="btn"
                        onClick={() => handleEdit(host)}
                        style={{ marginRight: '10px' }}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-danger"
                        onClick={() => handleDeleteClick(host.hostname)}
                        disabled={deleteLoading === host.hostname}
                      >
                        {deleteLoading === host.hostname ? 'Deleting...' : 'Delete'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {filteredHosts.length === 0 && searchTerm && hosts.length > 0 && (
        <div style={{ textAlign: 'center', padding: '20px', color: '#666' }}>
          No hosts match your search criteria.
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {confirmDelete && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: 'white',
            padding: '30px',
            borderRadius: '8px',
            maxWidth: '500px',
            width: '90%',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
          }}>
            <h3 style={{ marginTop: 0, marginBottom: '20px', color: '#e74c3c' }}>
              Confirm Delete
            </h3>
            <p style={{ marginBottom: '20px', fontSize: '16px' }}>
              Are you sure you want to delete host <strong>"{confirmDelete.hostname}"</strong>?
            </p>
            <p style={{ marginBottom: '20px', fontSize: '14px', color: '#666' }}>
              This action cannot be undone. The DHCP configuration will be updated immediately.
            </p>

            {deleteError && (
              <div className="alert alert-error" style={{ marginBottom: '20px' }}>
                {deleteError}
              </div>
            )}

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                className="btn"
                onClick={handleCancelDelete}
                disabled={deleteLoading !== null}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger"
                onClick={handleConfirmDelete}
                disabled={deleteLoading !== null}
              >
                {deleteLoading === confirmDelete.hostname ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default HostList;