/**
 * Main App Component
 * DHCP Configuration Manager - Web interface for managing ISC DHCP Server configuration
 */

import React, { useState, useEffect } from "react";
import HostList from "./components/HostList";
import HostForm from "./components/HostForm";
import ConfigViewer from "./components/ConfigViewer";
import apiService, { DHCPHost, APIError } from "./services/api";

type ActiveTab = "hosts" | "config";

function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("hosts");
  const [editingHost, setEditingHost] = useState<DHCPHost | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [appStatus, setAppStatus] = useState<{
    connected: boolean;
    error: string | null;
  }>({
    connected: true,
    error: null,
  });

  // Check backend connectivity on app load
  useEffect(() => {
    const checkConnection = async () => {
      try {
        await apiService.healthCheck();
        setAppStatus({ connected: true, error: null });
      } catch (err) {
        if (err instanceof APIError) {
          setAppStatus({
            connected: false,
            error: `Backend connection failed: ${err.message}`,
          });
        } else {
          setAppStatus({
            connected: false,
            error: "Unable to connect to backend server",
          });
        }
      }
    };

    checkConnection();
  }, []);

  const handleTabChange = (tab: ActiveTab) => {
    setActiveTab(tab);
    // Close any open forms when switching tabs
    setEditingHost(null);
    setShowAddForm(false);
  };

  const handleAddHost = () => {
    setEditingHost(null);
    setShowAddForm(true);
  };

  const handleEditHost = (host: DHCPHost) => {
    setEditingHost(host);
    setShowAddForm(true);
  };

  const handleFormSave = () => {
    setEditingHost(null);
    setShowAddForm(false);
    triggerRefresh();
  };

  const handleFormCancel = () => {
    setEditingHost(null);
    setShowAddForm(false);
  };

  const triggerRefresh = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const isFormVisible = showAddForm || editingHost !== null;

  return (
    <div>
      {/* Header */}
      <div className="header">
        <div className="container">
          <h1>DHCP Configuration Manager</h1>
        </div>
      </div>

      <div className="container">
        {/* Connection Status */}
        {!appStatus.connected && (
          <div className="alert alert-error">
            <strong>Backend Connection Error:</strong> {appStatus.error}
            <br />
            <small>
              Make sure the Flask backend is running on port 5000. Run{" "}
              <code>python backend/app.py</code> to start the server.
            </small>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="tabs">
          <button
            className={`tab ${activeTab === "hosts" ? "active" : ""}`}
            onClick={() => handleTabChange("hosts")}
          >
            Host Reservations
          </button>
          <button
            className={`tab ${activeTab === "config" ? "active" : ""}`}
            onClick={() => handleTabChange("config")}
          >
            Configuration
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === "hosts" && (
          <div>
            {!isFormVisible && (
              <div style={{ marginBottom: "20px" }}>
                <button
                  className="btn btn-success"
                  onClick={handleAddHost}
                  disabled={!appStatus.connected}
                >
                  Add Host Reservation
                </button>
              </div>
            )}

            {isFormVisible ? (
              <HostForm
                editingHost={editingHost}
                onSave={handleFormSave}
                onCancel={handleFormCancel}
              />
            ) : (
              <HostList
                onEditHost={handleEditHost}
                onRefresh={triggerRefresh}
                refreshTrigger={refreshTrigger}
              />
            )}
          </div>
        )}

        {activeTab === "config" && (
          <ConfigViewer refreshTrigger={refreshTrigger} />
        )}

        {/* Footer */}
        <div
          style={{
            marginTop: "40px",
            padding: "20px 0",
            borderTop: "1px solid #ddd",
            color: "#666",
            textAlign: "center",
            fontSize: "14px",
          }}
        >
          <p>
            DHCP Configuration Manager v1.0.0 - A web interface for managing ISC
            DHCP Server configuration
          </p>
          <p>
            <strong>⚠️ Important:</strong> Always validate configuration before
            restarting the DHCP service. Invalid configurations may cause
            service failures.
          </p>
        </div>
      </div>
    </div>
  );
}

export default App;
