/**
 * ConfigViewer Component
 * Displays the raw DHCP configuration file content with validation and service management
 */

import React, { useState, useEffect } from "react";
import apiService, {
  ServiceStatus,
  ConfigValidation,
  BackupInfo,
  APIError,
} from "../services/api";

interface ConfigViewerProps {
  refreshTrigger: number;
  showOnlyServiceStatus?: boolean;
}

const ConfigViewer: React.FC<ConfigViewerProps> = ({
  refreshTrigger,
  showOnlyServiceStatus = false,
}) => {
  const [config, setConfig] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [serviceStatus, setServiceStatus] = useState<ServiceStatus | null>(
    null
  );
  const [backendServiceStatus, setBackendServiceStatus] =
    useState<ServiceStatus | null>(null);
  const [nginxServiceStatus, setNginxServiceStatus] =
    useState<ServiceStatus | null>(null);
  const [validation, setValidation] = useState<ConfigValidation | null>(null);
  const [backups, setBackups] = useState<BackupInfo[]>([]);
  const [validating, setValidating] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [restartingBackend, setRestartingBackend] = useState(false);
  const [restartingNginx, setRestartingNginx] = useState(false);
  const [showRestartConfirm, setShowRestartConfirm] = useState(false);
  const [showBackendRestartConfirm, setShowBackendRestartConfirm] =
    useState(false);
  const [showNginxRestartConfirm, setShowNginxRestartConfirm] = useState(false);
  const [restartMessage, setRestartMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [backendRestartMessage, setBackendRestartMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [nginxRestartMessage, setNginxRestartMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const loadConfig = async () => {
    try {
      setLoading(true);
      setError(null);
      const configData = await apiService.getConfig();
      setConfig(configData.config);
    } catch (err) {
      if (err instanceof APIError) {
        setError(`Failed to load configuration: ${err.message}`);
      } else {
        setError("Failed to load configuration. Please check your connection.");
      }
    } finally {
      setLoading(false);
    }
  };

  const loadServiceStatus = async () => {
    try {
      const status = await apiService.getServiceStatus("isc-dhcp-server");
      setServiceStatus(status);
    } catch (err) {
      console.warn("Failed to load DHCP service status:", err);
    }
  };

  const loadBackendServiceStatus = async () => {
    try {
      const status = await apiService.getServiceStatus("dhcp-manager");
      setBackendServiceStatus(status);
    } catch (err) {
      console.warn("Failed to load backend service status:", err);
    }
  };

  const loadNginxServiceStatus = async () => {
    try {
      const status = await apiService.getServiceStatus("nginx");
      setNginxServiceStatus(status);
    } catch (err) {
      console.warn("Failed to load nginx service status:", err);
    }
  };

  const loadBackups = async () => {
    try {
      const backupData = await apiService.getBackups();
      setBackups(backupData);
    } catch (err) {
      console.warn("Failed to load backups:", err);
    }
  };

  useEffect(() => {
    if (showOnlyServiceStatus) {
      loadServiceStatus();
      loadBackendServiceStatus();
      loadNginxServiceStatus();
    } else {
      loadConfig();
      loadServiceStatus();
      loadBackups();
    }
  }, [refreshTrigger, showOnlyServiceStatus]);

  const handleValidate = async () => {
    try {
      setValidating(true);
      const result = await apiService.validateConfig();
      setValidation(result);
    } catch (err) {
      if (err instanceof APIError) {
        setValidation({
          valid: false,
          message: `Validation failed: ${err.message}`,
        });
      } else {
        setValidation({
          valid: false,
          message: "Validation failed due to network error",
        });
      }
    } finally {
      setValidating(false);
    }
  };

  const handleRestartClick = () => {
    setShowRestartConfirm(true);
    setRestartMessage(null);
  };

  const handleRestartConfirm = async () => {
    try {
      setRestarting(true);
      setShowRestartConfirm(false);
      const result = await apiService.restartService("isc-dhcp-server");
      await loadServiceStatus();
      setRestartMessage({
        type: "success",
        text: result.message || "DHCP service restarted successfully!",
      });
    } catch (err) {
      if (err instanceof APIError) {
        setRestartMessage({
          type: "error",
          text: err.message,
        });
      } else {
        setRestartMessage({
          type: "error",
          text: "Failed to restart service. Please try again.",
        });
      }
    } finally {
      setRestarting(false);
    }
  };

  const handleRestartCancel = () => {
    setShowRestartConfirm(false);
  };

  const handleBackendRestartClick = () => {
    setShowBackendRestartConfirm(true);
    setBackendRestartMessage(null);
  };

  const handleBackendRestartConfirm = async () => {
    try {
      setRestartingBackend(true);
      setShowBackendRestartConfirm(false);
      const result = await apiService.restartService("dhcp-manager");
      await loadBackendServiceStatus();
      setBackendRestartMessage({
        type: "success",
        text: result.message || "Backend service restarted successfully!",
      });
    } catch (err) {
      if (err instanceof APIError) {
        setBackendRestartMessage({
          type: "error",
          text: err.message,
        });
      } else {
        setBackendRestartMessage({
          type: "error",
          text: "Failed to restart backend service. Please try again.",
        });
      }
    } finally {
      setRestartingBackend(false);
    }
  };

  const handleBackendRestartCancel = () => {
    setShowBackendRestartConfirm(false);
  };

  const handleNginxRestartClick = () => {
    setShowNginxRestartConfirm(true);
    setNginxRestartMessage(null);
  };

  const handleNginxRestartConfirm = async () => {
    try {
      setRestartingNginx(true);
      setShowNginxRestartConfirm(false);
      const result = await apiService.restartService("nginx");
      await loadNginxServiceStatus();
      setNginxRestartMessage({
        type: "success",
        text: result.message || "Nginx service reloaded successfully!",
      });
    } catch (err) {
      if (err instanceof APIError) {
        setNginxRestartMessage({
          type: "error",
          text: err.message,
        });
      } else {
        setNginxRestartMessage({
          type: "error",
          text: "Failed to reload nginx service. Please try again.",
        });
      }
    } finally {
      setRestartingNginx(false);
    }
  };

  const handleNginxRestartCancel = () => {
    setShowNginxRestartConfirm(false);
  };

  const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  if (loading && !showOnlyServiceStatus) {
    return (
      <div className="card">
        <div className="loading">Loading configuration...</div>
      </div>
    );
  }

  if (showOnlyServiceStatus) {
    return (
      <div>
        {/* DHCP Service Restart Confirmation Modal */}
        {showRestartConfirm && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: "rgba(0, 0, 0, 0.5)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 1000,
            }}
          >
            <div
              style={{
                backgroundColor: "white",
                padding: "30px",
                borderRadius: "8px",
                maxWidth: "500px",
                width: "90%",
                boxShadow: "0 4px 6px rgba(0, 0, 0, 0.1)",
              }}
            >
              <h3 style={{ marginTop: 0, marginBottom: "15px" }}>
                Confirm ISC DHCP Service Restart
              </h3>
              <p style={{ marginBottom: "20px", color: "#666" }}>
                Are you sure you want to restart the DHCP service? This may
                temporarily interrupt network services.
              </p>
              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  justifyContent: "flex-end",
                }}
              >
                <button
                  className="btn"
                  onClick={handleRestartCancel}
                  style={{ background: "#95a5a6" }}
                >
                  Cancel
                </button>
                <button
                  className="btn"
                  onClick={handleRestartConfirm}
                  style={{ background: "#e74c3c" }}
                >
                  Restart Service
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Nginx Service Restart Confirmation Modal */}
        {showNginxRestartConfirm && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: "rgba(0, 0, 0, 0.5)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 1000,
            }}
          >
            <div
              style={{
                backgroundColor: "white",
                padding: "30px",
                borderRadius: "8px",
                maxWidth: "500px",
                width: "90%",
                boxShadow: "0 4px 6px rgba(0, 0, 0, 0.1)",
              }}
            >
              <h3 style={{ marginTop: 0, marginBottom: "15px" }}>
                Confirm Nginx Service Reload
              </h3>
              <p style={{ marginBottom: "20px", color: "#666" }}>
                Are you sure you want to reload the nginx service? The
                configuration will be tested before reloading.
              </p>
              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  justifyContent: "flex-end",
                }}
              >
                <button
                  className="btn"
                  onClick={handleNginxRestartCancel}
                  style={{ background: "#95a5a6" }}
                >
                  Cancel
                </button>
                <button
                  className="btn"
                  onClick={handleNginxRestartConfirm}
                  style={{ background: "#e74c3c" }}
                >
                  Reload Service
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Backend Service Restart Confirmation Modal */}
        {showBackendRestartConfirm && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: "rgba(0, 0, 0, 0.5)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 1000,
            }}
          >
            <div
              style={{
                backgroundColor: "white",
                padding: "30px",
                borderRadius: "8px",
                maxWidth: "500px",
                width: "90%",
                boxShadow: "0 4px 6px rgba(0, 0, 0, 0.1)",
              }}
            >
              <h3 style={{ marginTop: 0, marginBottom: "15px" }}>
                Confirm Backend Service Restart
              </h3>
              <p style={{ marginBottom: "20px", color: "#666" }}>
                Are you sure you want to restart the backend service? This will
                temporarily disconnect the web interface.
              </p>
              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  justifyContent: "flex-end",
                }}
              >
                <button
                  className="btn"
                  onClick={handleBackendRestartCancel}
                  style={{ background: "#95a5a6" }}
                >
                  Cancel
                </button>
                <button
                  className="btn"
                  onClick={handleBackendRestartConfirm}
                  style={{ background: "#e74c3c" }}
                >
                  Restart Service
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Service Status Card */}
        {serviceStatus && (
          <div className="card">
            <h3>DHCP Service Status</h3>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "15px",
                marginBottom: "15px",
              }}
            >
              <div>
                <strong>Service:</strong> {serviceStatus.service}
              </div>
              <div>
                <strong>Status:</strong>{" "}
                <span
                  style={{
                    color: serviceStatus.active ? "#27ae60" : "#e74c3c",
                    fontWeight: "bold",
                  }}
                >
                  {serviceStatus.status}
                </span>
              </div>
              <button
                className="btn"
                onClick={handleRestartClick}
                disabled={restarting}
              >
                {restarting ? "Restarting..." : "Restart Service"}
              </button>
            </div>

            {restartMessage && (
              <div
                className={`alert ${
                  restartMessage.type === "success"
                    ? "alert-success"
                    : "alert-error"
                }`}
                style={{ marginTop: "15px" }}
              >
                <pre
                  style={{
                    margin: 0,
                    whiteSpace: "pre-wrap",
                    fontFamily: "inherit",
                    fontSize: "inherit",
                  }}
                >
                  {restartMessage.text}
                </pre>
              </div>
            )}

            {serviceStatus.details && (
              <details>
                <summary style={{ cursor: "pointer", marginBottom: "10px" }}>
                  View Service Details
                </summary>
                <pre
                  style={{
                    background: "#f8f9fa",
                    padding: "10px",
                    borderRadius: "4px",
                    fontSize: "12px",
                    overflow: "auto",
                    maxHeight: "200px",
                  }}
                >
                  {serviceStatus.details}
                </pre>
              </details>
            )}
          </div>
        )}

        {/* Backend Service Status Card */}
        {backendServiceStatus && (
          <div className="card">
            <h3>DHCP Manager Service Status</h3>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "15px",
                marginBottom: "15px",
              }}
            >
              <div>
                <strong>Service:</strong> {backendServiceStatus.service}
              </div>
              <div>
                <strong>Status:</strong>{" "}
                <span
                  style={{
                    color: backendServiceStatus.active ? "#27ae60" : "#e74c3c",
                    fontWeight: "bold",
                  }}
                >
                  {backendServiceStatus.status}
                </span>
              </div>
              <button
                className="btn"
                onClick={handleBackendRestartClick}
                disabled={restartingBackend}
              >
                {restartingBackend ? "Restarting..." : "Restart Service"}
              </button>
            </div>

            {backendRestartMessage && (
              <div
                className={`alert ${
                  backendRestartMessage.type === "success"
                    ? "alert-success"
                    : "alert-error"
                }`}
                style={{ marginTop: "15px" }}
              >
                <pre
                  style={{
                    margin: 0,
                    whiteSpace: "pre-wrap",
                    fontFamily: "inherit",
                    fontSize: "inherit",
                  }}
                >
                  {backendRestartMessage.text}
                </pre>
              </div>
            )}

            {backendServiceStatus.details && (
              <details>
                <summary style={{ cursor: "pointer", marginBottom: "10px" }}>
                  View Service Details
                </summary>
                <pre
                  style={{
                    background: "#f8f9fa",
                    padding: "10px",
                    borderRadius: "4px",
                    fontSize: "12px",
                    overflow: "auto",
                    maxHeight: "200px",
                  }}
                >
                  {backendServiceStatus.details}
                </pre>
              </details>
            )}
          </div>
        )}

        {/* Nginx Service Status Card */}
        {nginxServiceStatus && (
          <div className="card">
            <h3>Nginx Service Status</h3>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "15px",
                marginBottom: "15px",
              }}
            >
              <div>
                <strong>Service:</strong> {nginxServiceStatus.service}
              </div>
              <div>
                <strong>Status:</strong>{" "}
                <span
                  style={{
                    color: nginxServiceStatus.active ? "#27ae60" : "#e74c3c",
                    fontWeight: "bold",
                  }}
                >
                  {nginxServiceStatus.status}
                </span>
              </div>
              <button
                className="btn"
                onClick={handleNginxRestartClick}
                disabled={restartingNginx}
                style={{ background: "#3498db" }}
              >
                {restartingNginx ? "Reloading..." : "Reload Service"}
              </button>
            </div>

            {nginxRestartMessage && (
              <div
                className={`alert ${
                  nginxRestartMessage.type === "success"
                    ? "alert-success"
                    : "alert-error"
                }`}
                style={{ marginTop: "15px" }}
              >
                <pre
                  style={{
                    margin: 0,
                    whiteSpace: "pre-wrap",
                    fontFamily: "inherit",
                    fontSize: "inherit",
                  }}
                >
                  {nginxRestartMessage.text}
                </pre>
              </div>
            )}

            {nginxServiceStatus.details && (
              <details>
                <summary style={{ cursor: "pointer", marginBottom: "10px" }}>
                  View Service Details
                </summary>
                <pre
                  style={{
                    background: "#f8f9fa",
                    padding: "10px",
                    borderRadius: "4px",
                    fontSize: "12px",
                    overflow: "auto",
                    maxHeight: "200px",
                  }}
                >
                  {nginxServiceStatus.details}
                </pre>
              </details>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      {/* Configuration Validation Card */}
      <div className="card">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "15px",
          }}
        >
          <h3>Configuration Validation</h3>
          <button
            className="btn"
            onClick={handleValidate}
            disabled={validating}
          >
            {validating ? "Validating..." : "Validate Config"}
          </button>
        </div>

        {validation && (
          <div
            className={`alert ${
              validation.valid ? "alert-success" : "alert-error"
            }`}
          >
            <strong>{validation.valid ? "✓ Valid" : "✗ Invalid"}:</strong>{" "}
            {validation.message}
          </div>
        )}
      </div>

      {/* Configuration Content Card */}
      <div className="card">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "15px",
          }}
        >
          <h3>DHCP Configuration File</h3>
          <button className="btn" onClick={loadConfig} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        {config ? (
          <div className="config-viewer">{config}</div>
        ) : (
          <div style={{ textAlign: "center", padding: "40px", color: "#666" }}>
            <p>No configuration content available.</p>
          </div>
        )}

        <div style={{ marginTop: "10px", fontSize: "14px", color: "#666" }}>
          <strong>File Path:</strong> /etc/dhcp/dhcpd.conf
        </div>
      </div>

      {/* Backups Card */}
      {backups.length > 0 && (
        <div className="card">
          <h3>Configuration Backups</h3>
          <p style={{ color: "#666", marginBottom: "15px" }}>
            Automatic backups are created before each configuration change.
          </p>

          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Backup File</th>
                  <th>Created</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                {backups.slice(0, 10).map((backup) => (
                  <tr key={backup.filename}>
                    <td>
                      <code>{backup.filename}</code>
                    </td>
                    <td>{formatTimestamp(backup.timestamp)}</td>
                    <td>{formatFileSize(backup.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {backups.length > 10 && (
            <div style={{ marginTop: "10px", color: "#666", fontSize: "14px" }}>
              Showing 10 most recent backups. Total: {backups.length}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ConfigViewer;
