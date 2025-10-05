/**
 * SubnetList Component
 * Displays a table of DHCP subnet declarations with edit/delete functionality
 */

import React, { useState, useEffect } from 'react';
import apiService, { DHCPSubnet, APIError } from '../services/api';

interface SubnetListProps {
  onEditSubnet: (subnet: DHCPSubnet) => void;
  onRefresh: () => void;
  refreshTrigger: number;
}

const SubnetList: React.FC<SubnetListProps> = ({ onEditSubnet, onRefresh, refreshTrigger }) => {
  const [subnets, setSubnets] = useState<DHCPSubnet[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [deleteLoading, setDeleteLoading] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ network: string } | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const loadSubnets = async () => {
    try {
      setLoading(true);
      setError(null);
      const subnetData = await apiService.getSubnets();
      setSubnets(subnetData);
    } catch (err) {
      if (err instanceof APIError) {
        setError(`Failed to load subnets: ${err.message}`);
      } else {
        setError('Failed to load subnets. Please check your connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSubnets();
  }, [refreshTrigger]);

  const handleDeleteClick = (network: string) => {
    setConfirmDelete({ network });
    setDeleteError(null);
  };

  const handleCancelDelete = () => {
    setConfirmDelete(null);
    setDeleteError(null);
  };

  const handleConfirmDelete = async () => {
    if (!confirmDelete) return;

    const network = confirmDelete.network;

    try {
      setDeleteLoading(network);
      setDeleteError(null);
      await apiService.deleteSubnet(network);
      await loadSubnets();
      onRefresh();
      setConfirmDelete(null);
    } catch (err) {
      if (err instanceof APIError) {
        setDeleteError(`Failed to delete subnet: ${err.message}`);
      } else {
        setDeleteError('Failed to delete subnet. Please try again.');
      }
    } finally {
      setDeleteLoading(null);
    }
  };

  const handleEdit = (subnet: DHCPSubnet) => {
    onEditSubnet(subnet);
  };

  // Filter subnets based on search term
  const filteredSubnets = subnets.filter(subnet =>
    subnet.network.includes(searchTerm) ||
    subnet.netmask.includes(searchTerm) ||
    (subnet.range_start && subnet.range_start.includes(searchTerm)) ||
    (subnet.range_end && subnet.range_end.includes(searchTerm))
  );

  // Calculate CIDR notation from netmask
  const netmaskToCIDR = (netmask: string): number => {
    const parts = netmask.split('.').map(Number);
    const binary = parts.map(part => part.toString(2).padStart(8, '0')).join('');
    return binary.split('1').length - 1;
  };

  if (loading) {
    return (
      <div className="card">
        <div className="loading">Loading subnets...</div>
      </div>
    );
  }

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>DHCP Subnets</h2>
        <button
          className="btn"
          onClick={loadSubnets}
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
          placeholder="Search subnets by network, netmask, or range..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ maxWidth: '400px' }}
        />
      </div>

      {subnets.length === 0 && !loading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
          <p>No DHCP subnets found.</p>
          <p>Click "Add Subnet" to create your first subnet.</p>
        </div>
      ) : (
        <>
          <div style={{ marginBottom: '10px', color: '#666' }}>
            Showing {filteredSubnets.length} of {subnets.length} subnets
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Network</th>
                  <th>Netmask (CIDR)</th>
                  <th>DHCP Range</th>
                  <th>Options</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredSubnets.map((subnet) => (
                  <tr key={subnet.network}>
                    <td>
                      <strong><code>{subnet.network}</code></strong>
                    </td>
                    <td>
                      <code>{subnet.netmask}</code> (/{netmaskToCIDR(subnet.netmask)})
                    </td>
                    <td>
                      {subnet.range_start && subnet.range_end ? (
                        <code>{subnet.range_start} - {subnet.range_end}</code>
                      ) : (
                        <span style={{ color: '#999' }}>No range</span>
                      )}
                    </td>
                    <td>
                      {subnet.options && Object.keys(subnet.options).length > 0 ? (
                        <div style={{ fontSize: '12px' }}>
                          {Object.entries(subnet.options).slice(0, 2).map(([key, value]) => (
                            <div key={key}>{key}: {value}</div>
                          ))}
                          {Object.keys(subnet.options).length > 2 && (
                            <div style={{ color: '#666' }}>+{Object.keys(subnet.options).length - 2} more...</div>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: '#999' }}>No options</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="btn"
                        onClick={() => handleEdit(subnet)}
                        style={{ marginRight: '10px' }}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-danger"
                        onClick={() => handleDeleteClick(subnet.network)}
                        disabled={deleteLoading === subnet.network}
                      >
                        {deleteLoading === subnet.network ? 'Deleting...' : 'Delete'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {filteredSubnets.length === 0 && searchTerm && subnets.length > 0 && (
        <div style={{ textAlign: 'center', padding: '20px', color: '#666' }}>
          No subnets match your search criteria.
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
            backgroundColor: 'var(--bg-modal)',
            padding: '30px',
            borderRadius: '8px',
            maxWidth: '500px',
            width: '90%',
            boxShadow: '0 4px 6px var(--shadow)'
          }}>
            <h3 style={{ marginTop: 0, marginBottom: '20px', color: '#e74c3c' }}>
              Confirm Delete
            </h3>
            <p style={{ marginBottom: '20px', fontSize: '16px', color: 'var(--text-primary)' }}>
              Are you sure you want to delete subnet <strong>"{confirmDelete.network}"</strong>?
            </p>
            <p style={{ marginBottom: '20px', fontSize: '14px', color: 'var(--text-secondary)' }}>
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
                {deleteLoading === confirmDelete.network ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SubnetList;
