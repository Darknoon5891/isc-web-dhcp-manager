/**
 * ZoneList Component
 * Displays a table of DHCP zone declarations with edit/delete functionality
 */

import React, { useState, useEffect } from 'react';
import apiService, { DHCPZone, APIError } from '../services/api';

interface ZoneListProps {
  onEditZone: (zone: DHCPZone) => void;
  onRefresh: () => void;
  refreshTrigger: number;
}

const ZoneList: React.FC<ZoneListProps> = ({ onEditZone, onRefresh, refreshTrigger }) => {
  const [zones, setZones] = useState<DHCPZone[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [deleteLoading, setDeleteLoading] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ zone_name: string } | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const loadZones = async () => {
    try {
      setLoading(true);
      setError(null);
      const zoneData = await apiService.getZones();
      setZones(zoneData);
    } catch (err) {
      if (err instanceof APIError) {
        setError(`Failed to load zones: ${err.message}`);
      } else {
        setError('Failed to load zones. Please check your connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadZones();
  }, [refreshTrigger]);

  const handleDeleteClick = (zone_name: string) => {
    setConfirmDelete({ zone_name });
    setDeleteError(null);
  };

  const handleCancelDelete = () => {
    setConfirmDelete(null);
    setDeleteError(null);
  };

  const handleConfirmDelete = async () => {
    if (!confirmDelete) return;

    const zone_name = confirmDelete.zone_name;

    try {
      setDeleteLoading(zone_name);
      setDeleteError(null);
      await apiService.deleteZone(zone_name);
      await loadZones();
      onRefresh();
      setConfirmDelete(null);
    } catch (err) {
      if (err instanceof APIError) {
        setDeleteError(`Failed to delete zone: ${err.message}`);
      } else {
        setDeleteError('Failed to delete zone. Please try again.');
      }
    } finally {
      setDeleteLoading(null);
    }
  };

  const handleEdit = (zone: DHCPZone) => {
    onEditZone(zone);
  };

  // Filter zones based on search term
  const filteredZones = zones.filter(zone =>
    zone.zone_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    zone.primary.includes(searchTerm) ||
    (zone.key_name && zone.key_name.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  // Determine zone type
  const getZoneType = (zoneName: string): string => {
    if (zoneName.includes('in-addr.arpa')) return 'Reverse (PTR)';
    if (zoneName.includes('ip6.arpa')) return 'Reverse IPv6';
    return 'Forward';
  };

  if (loading) {
    return (
      <div className="card">
        <div className="loading">Loading PTR zones...</div>
      </div>
    );
  }

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>DNS Update Zones (PTR Records)</h2>
        <button
          className="btn"
          onClick={loadZones}
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
          placeholder="Search zones by name, primary server, or key..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ maxWidth: '400px' }}
        />
      </div>

      {zones.length === 0 && !loading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
          <p>No DNS update zones configured.</p>
          <p>Click "Add PTR Zone" to enable dynamic DNS updates.</p>
        </div>
      ) : (
        <>
          <div style={{ marginBottom: '10px', color: '#666' }}>
            Showing {filteredZones.length} of {zones.length} zones
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Zone Name</th>
                  <th>Type</th>
                  <th>Primary DNS</th>
                  <th>Key</th>
                  <th>Secondary Servers</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredZones.map((zone) => (
                  <tr key={zone.zone_name}>
                    <td>
                      <strong><code>{zone.zone_name}</code></strong>
                    </td>
                    <td>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '12px',
                        backgroundColor: getZoneType(zone.zone_name).includes('Reverse') ? '#e3f2fd' : '#f3e5f5',
                        color: getZoneType(zone.zone_name).includes('Reverse') ? '#1976d2' : '#7b1fa2'
                      }}>
                        {getZoneType(zone.zone_name)}
                      </span>
                    </td>
                    <td>
                      <code>{zone.primary}</code>
                    </td>
                    <td>
                      {zone.key_name ? (
                        <code>{zone.key_name}</code>
                      ) : (
                        <span style={{ color: '#999' }}>No key</span>
                      )}
                    </td>
                    <td>
                      {zone.secondary && zone.secondary.length > 0 ? (
                        <div style={{ fontSize: '12px' }}>
                          {zone.secondary.slice(0, 2).map((sec, idx) => (
                            <div key={idx}><code>{sec}</code></div>
                          ))}
                          {zone.secondary.length > 2 && (
                            <div style={{ color: '#666' }}>+{zone.secondary.length - 2} more...</div>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: '#999' }}>None</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="btn"
                        onClick={() => handleEdit(zone)}
                        style={{ marginRight: '10px' }}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-danger"
                        onClick={() => handleDeleteClick(zone.zone_name)}
                        disabled={deleteLoading === zone.zone_name}
                      >
                        {deleteLoading === zone.zone_name ? 'Deleting...' : 'Delete'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {filteredZones.length === 0 && searchTerm && zones.length > 0 && (
        <div style={{ textAlign: 'center', padding: '20px', color: '#666' }}>
          No zones match your search criteria.
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
              Are you sure you want to delete zone <strong>"{confirmDelete.zone_name}"</strong>?
            </p>
            <p style={{ marginBottom: '20px', fontSize: '14px', color: 'var(--text-secondary)' }}>
              This action cannot be undone. DNS updates for this zone will no longer be processed.
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
                {deleteLoading === confirmDelete.zone_name ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ZoneList;
