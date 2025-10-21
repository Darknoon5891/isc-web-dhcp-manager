/**
 * Main App Component
 * ISC Web DHCP Configuration Manager - Web interface for managing ISC DHCP Server configuration
 */

import React, { useState, useEffect } from "react";
import HostList from "./components/HostList";
import HostForm from "./components/HostForm";
import SubnetList from "./components/SubnetList";
import SubnetForm from "./components/SubnetForm";
import ZoneList from "./components/ZoneList";
import ZoneForm from "./components/ZoneForm";
import LeaseList from "./components/LeaseList";
import GlobalConfigForm from "./components/GlobalConfigForm";
import ConfigViewer from "./components/ConfigViewer";
import AppSettingsForm from "./components/AppSettingsForm";
import Login from "./components/Login";
import apiService, {
  DHCPHost,
  DHCPSubnet,
  DHCPZone,
  APIError,
} from "./services/api";
import moonIcon from "./assets/moon.png";
import sunIcon from "./assets/sun.png";

type ActiveTab =
  | "hosts"
  | "subnets"
  | "zones"
  | "leases"
  | "global"
  | "config"
  | "appsettings";

function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("hosts");
  const [editingHost, setEditingHost] = useState<DHCPHost | null>(null);
  const [editingSubnet, setEditingSubnet] = useState<DHCPSubnet | null>(null);
  const [editingZone, setEditingZone] = useState<DHCPZone | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [hostname, setHostname] = useState<string>("Loading...");
  const [appStatus, setAppStatus] = useState<{
    connected: boolean;
    error: string | null;
  }>({
    connected: true,
    error: null,
  });
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem("darkMode");
    return saved === "true";
  });

  // Apply dark mode class to body
  useEffect(() => {
    if (darkMode) {
      document.body.classList.add("dark-mode");
    } else {
      document.body.classList.remove("dark-mode");
    }
    localStorage.setItem("darkMode", darkMode.toString());
  }, [darkMode]);

  // Check authentication on app load
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem("auth_token");

      if (!token) {
        setIsAuthenticated(false);
        setIsCheckingAuth(false);
        return;
      }

      try {
        const result = await apiService.verifyToken();
        setIsAuthenticated(result.valid);
      } catch (err) {
        setIsAuthenticated(false);
        localStorage.removeItem("auth_token");
      } finally {
        setIsCheckingAuth(false);
      }
    };

    checkAuth();
  }, []);

  // Check backend connectivity after authentication
  useEffect(() => {
    if (!isAuthenticated || isCheckingAuth) {
      return;
    }

    const checkConnection = async () => {
      try {
        await apiService.healthCheck();
        setAppStatus({ connected: true, error: null });

        // Fetch hostname
        const hostnameData = await apiService.getSystemHostname();
        setHostname(hostnameData.hostname);
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
  }, [isAuthenticated, isCheckingAuth]);

  const handleTabChange = (tab: ActiveTab) => {
    setActiveTab(tab);
    // Close any open forms when switching tabs
    setEditingHost(null);
    setEditingSubnet(null);
    setEditingZone(null);
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

  const handleAddSubnet = () => {
    setEditingSubnet(null);
    setShowAddForm(true);
  };

  const handleEditSubnet = (subnet: DHCPSubnet) => {
    setEditingSubnet(subnet);
    setShowAddForm(true);
  };

  const handleAddZone = () => {
    setEditingZone(null);
    setShowAddForm(true);
  };

  const handleEditZone = (zone: DHCPZone) => {
    setEditingZone(zone);
    setShowAddForm(true);
  };

  const handleFormSave = () => {
    setEditingHost(null);
    setEditingSubnet(null);
    setEditingZone(null);
    setShowAddForm(false);
    triggerRefresh();
  };

  const handleFormCancel = () => {
    setEditingHost(null);
    setEditingSubnet(null);
    setEditingZone(null);
    setShowAddForm(false);
  };

  const triggerRefresh = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const handleLogin = (token: string) => {
    localStorage.setItem("auth_token", token);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    apiService.logout();
  };

  const isFormVisible =
    showAddForm ||
    editingHost !== null ||
    editingSubnet !== null ||
    editingZone !== null;

  // Show loading while checking authentication
  if (isCheckingAuth) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          minHeight: "100vh",
        }}
      >
        <div className="loading">Checking authentication...</div>
      </div>
    );
  }

  // Show login if not authenticated
  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLogin} />;
  }

  return (
    <div>
      {/* Header */}
      <div className="header">
        <div className="container">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <h1>ISC Web DHCP Configuration Manager</h1>
              <p
                style={{
                  margin: "10px 0 0 0",
                  fontSize: "14px",
                  opacity: 0.9,
                  fontWeight: "bold",
                }}
              >
                Server: {hostname}
              </p>
            </div>
            <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
              <button
                className="dark-mode-toggle"
                onClick={() => setDarkMode(!darkMode)}
                title={
                  darkMode ? "Switch to Light Mode" : "Switch to Dark Mode"
                }
              >
                <img
                  src={darkMode ? sunIcon : moonIcon}
                  alt={darkMode ? "Light mode" : "Dark mode"}
                  style={{ width: "24px", height: "24px" }}
                />
              </button>
              <button
                className="btn"
                onClick={handleLogout}
                style={{
                  background: "#e74c3c",
                }}
              >
                Logout
              </button>
            </div>
          </div>
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
            className={`tab ${activeTab === "subnets" ? "active" : ""}`}
            onClick={() => handleTabChange("subnets")}
          >
            Subnets
          </button>
          <button
            className={`tab ${activeTab === "zones" ? "active" : ""}`}
            onClick={() => handleTabChange("zones")}
          >
            PTR Zones
          </button>
          <button
            className={`tab ${activeTab === "leases" ? "active" : ""}`}
            onClick={() => handleTabChange("leases")}
          >
            Leases
          </button>
          <button
            className={`tab ${activeTab === "global" ? "active" : ""}`}
            onClick={() => handleTabChange("global")}
          >
            Global DHCP Configuration
          </button>
          <button
            className={`tab ${activeTab === "config" ? "active" : ""}`}
            onClick={() => handleTabChange("config")}
          >
            DHCP Services Management
          </button>
          <button
            className={`tab ${activeTab === "appsettings" ? "active" : ""}`}
            onClick={() => handleTabChange("appsettings")}
          >
            App Settings
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

        {activeTab === "subnets" && (
          <div>
            {!isFormVisible && (
              <div style={{ marginBottom: "20px" }}>
                <button
                  className="btn btn-success"
                  onClick={handleAddSubnet}
                  disabled={!appStatus.connected}
                >
                  Add Subnet
                </button>
              </div>
            )}

            {isFormVisible && editingSubnet !== null ? (
              <SubnetForm
                editingSubnet={editingSubnet}
                onSave={handleFormSave}
                onCancel={handleFormCancel}
              />
            ) : isFormVisible && !editingHost ? (
              <SubnetForm
                editingSubnet={null}
                onSave={handleFormSave}
                onCancel={handleFormCancel}
              />
            ) : (
              <SubnetList
                onEditSubnet={handleEditSubnet}
                onRefresh={triggerRefresh}
                refreshTrigger={refreshTrigger}
              />
            )}
          </div>
        )}

        {activeTab === "zones" && (
          <div>
            {!isFormVisible && (
              <div style={{ marginBottom: "20px" }}>
                <button
                  className="btn btn-success"
                  onClick={handleAddZone}
                  disabled={!appStatus.connected}
                >
                  Add PTR Zone
                </button>
              </div>
            )}

            {isFormVisible && editingZone !== null ? (
              <ZoneForm
                editingZone={editingZone}
                onSave={handleFormSave}
                onCancel={handleFormCancel}
              />
            ) : isFormVisible && !editingHost && !editingSubnet ? (
              <ZoneForm
                editingZone={null}
                onSave={handleFormSave}
                onCancel={handleFormCancel}
              />
            ) : (
              <ZoneList
                onEditZone={handleEditZone}
                onRefresh={triggerRefresh}
                refreshTrigger={refreshTrigger}
              />
            )}
          </div>
        )}

        {activeTab === "leases" && (
          <LeaseList refreshTrigger={refreshTrigger} />
        )}

        {activeTab === "global" && (
          <div>
            <GlobalConfigForm refreshTrigger={refreshTrigger} />
            <div style={{ marginTop: "30px" }}>
              <ConfigViewer
                refreshTrigger={refreshTrigger}
                showOnlyServiceStatus={false}
              />
            </div>
          </div>
        )}

        {activeTab === "config" && (
          <ConfigViewer
            refreshTrigger={refreshTrigger}
            showOnlyServiceStatus={true}
          />
        )}

        {activeTab === "appsettings" && (
          <AppSettingsForm refreshTrigger={refreshTrigger} />
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
            ISC Web DHCP Configuration Manager v1.0.0 - A web interface for
            managing ISC DHCP Server configuration
          </p>
          <p>
            <strong>Important:</strong> Always validate configuration before
            restarting the DHCP service. Invalid configurations may cause
            service failures.
          </p>
        </div>
      </div>
    </div>
  );
}

export default App;
