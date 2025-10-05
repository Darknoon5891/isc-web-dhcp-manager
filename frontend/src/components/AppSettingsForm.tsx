/**
 * AppSettingsForm Component
 * Manages application configuration settings from /etc/isc-web-dhcp-manager/config.conf
 */

import React, { useState, useEffect } from "react";
import apiService, { APIError, TLSCertificateInfo } from "../services/api";

interface AppSettingsFormProps {
  refreshTrigger: number;
}

interface ConfigSchema {
  properties: {
    [key: string]: {
      type: string;
      description?: string;
      readOnly?: boolean;
      section?: string;
      order?: number;
      sensitive?: boolean;
      enum?: string[];
      minimum?: number;
      maximum?: number;
      default?: string;
    };
  };
  required: string[];
}

const AppSettingsForm: React.FC<AppSettingsFormProps> = ({
  refreshTrigger,
}) => {
  const [config, setConfig] = useState<{ [key: string]: string }>({});
  const [schema, setSchema] = useState<ConfigSchema | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);
  const [certInfo, setCertInfo] = useState<TLSCertificateInfo | null>(null);
  const [certLoading, setCertLoading] = useState(false);
  const [certError, setCertError] = useState<string | null>(null);
  const [validationMessage, setValidationMessage] = useState<string | null>(
    null
  );
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordChanging, setPasswordChanging] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, [refreshTrigger]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [configData, schemaData] = await Promise.all([
        apiService.getAppConfig(),
        apiService.getAppConfigSchema(),
      ]);

      setConfig(configData);
      setSchema(schemaData);
      setHasChanges(false);

      // Load TLS certificate info if TLS is enabled
      if (configData.TLS_ENABLED === "true") {
        loadCertificateInfo();
      }
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

  const loadCertificateInfo = async () => {
    try {
      setCertLoading(true);
      setCertError(null);
      const info = await apiService.getTLSCertificateInfo();
      setCertInfo(info);
    } catch (err) {
      if (err instanceof APIError) {
        setCertError(`Failed to load certificate info: ${err.message}`);
      } else {
        setCertError("Failed to load certificate information.");
      }
    } finally {
      setCertLoading(false);
    }
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordMessage(null);
    setPasswordError(null);

    // Validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordError("All fields are required");
      return;
    }

    if (newPassword.length < 8) {
      setPasswordError("New password must be at least 8 characters");
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords do not match");
      return;
    }

    try {
      setPasswordChanging(true);
      await apiService.changePassword(currentPassword, newPassword);
      setPasswordMessage("Password changed successfully!");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      if (err instanceof APIError) {
        setPasswordError(err.message);
      } else {
        setPasswordError("Failed to change password");
      }
    } finally {
      setPasswordChanging(false);
    }
  };

  const handleFieldChange = (key: string, value: string) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
    setHasChanges(true);
    setSuccessMessage(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      setSaving(true);
      setError(null);
      setSuccessMessage(null);

      await apiService.updateAppConfig(config);
      setSuccessMessage("Configuration saved successfully!");
      setHasChanges(false);

      // Reload to get masked values
      const updatedConfig = await apiService.getAppConfig();
      setConfig(updatedConfig);
    } catch (err) {
      if (err instanceof APIError) {
        setError(`Failed to save configuration: ${err.message}`);
      } else {
        setError("Failed to save configuration. Please try again.");
      }
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    loadData();
    setHasChanges(false);
    setSuccessMessage(null);
    setError(null);
  };

  const renderField = (
    key: string,
    props: ConfigSchema["properties"][string]
  ) => {
    const value = config[key] || "";
    const isReadOnly = props.readOnly || false;
    const isSensitive = props.sensitive || false;

    return (
      <div key={key} style={{ marginBottom: "20px" }}>
        <label
          style={{
            display: "block",
            marginBottom: "5px",
            fontWeight: "bold",
            fontSize: "14px",
          }}
        >
          {key}
          {isReadOnly && (
            <span
              style={{
                marginLeft: "8px",
                fontSize: "12px",
                fontWeight: "normal",
                color: "#666",
                fontStyle: "italic",
              }}
            >
              (read-only)
            </span>
          )}
          {isSensitive && !isReadOnly && (
            <span
              style={{
                marginLeft: "8px",
                fontSize: "12px",
                fontWeight: "normal",
                color: "#e74c3c",
              }}
            >
              (sensitive)
            </span>
          )}
        </label>

        {props.description && (
          <p
            style={{
              margin: "0 0 8px 0",
              fontSize: "13px",
              color: "#666",
            }}
          >
            {props.description}
          </p>
        )}

        {props.enum ? (
          <select
            value={value}
            onChange={(e) => handleFieldChange(key, e.target.value)}
            disabled={isReadOnly || saving}
            style={{
              width: "100%",
              padding: "8px",
              fontSize: "14px",
              border: "1px solid #ddd",
              borderRadius: "4px",
              backgroundColor: isReadOnly ? "#f5f5f5" : "white",
            }}
          >
            {props.enum.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        ) : props.type === "boolean" ? (
          <select
            value={value}
            onChange={(e) => handleFieldChange(key, e.target.value)}
            disabled={isReadOnly || saving}
            style={{
              width: "100%",
              padding: "8px",
              fontSize: "14px",
              border: "1px solid #ddd",
              borderRadius: "4px",
              backgroundColor: isReadOnly ? "#f5f5f5" : "white",
            }}
          >
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        ) : (
          <input
            type={props.type === "integer" ? "number" : "text"}
            value={value}
            onChange={(e) => handleFieldChange(key, e.target.value)}
            disabled={isReadOnly || saving}
            min={props.minimum}
            max={props.maximum}
            style={{
              width: "100%",
              padding: "8px",
              fontSize: "14px",
              border: "1px solid #ddd",
              borderRadius: "4px",
              backgroundColor: isReadOnly ? "#f5f5f5" : "white",
              fontFamily: isSensitive ? "monospace" : "inherit",
            }}
          />
        )}
      </div>
    );
  };

  const renderPasswordChange = () => {
    if (config.AUTH_ENABLED !== "true") {
      return null;
    }

    return (
      <div
        style={{
          marginTop: "30px",
          padding: "20px",
          background: "#f8f9fa",
          border: "1px solid #dee2e6",
          borderRadius: "4px",
        }}
      >
        <h3 style={{ marginTop: 0, marginBottom: "15px" }}>Change Password</h3>

        {passwordError && (
          <div className="alert alert-error" style={{ marginBottom: "15px" }}>
            {passwordError}
          </div>
        )}

        {passwordMessage && (
          <div className="alert alert-success" style={{ marginBottom: "15px" }}>
            {passwordMessage}
          </div>
        )}

        <form onSubmit={handlePasswordChange}>
          <div style={{ marginBottom: "15px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "5px",
                fontWeight: "bold",
                fontSize: "14px",
              }}
            >
              Current Password
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              disabled={passwordChanging}
              style={{
                width: "100%",
                padding: "8px",
                fontSize: "14px",
                border: "1px solid #ddd",
                borderRadius: "4px",
              }}
            />
          </div>

          <div style={{ marginBottom: "15px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "5px",
                fontWeight: "bold",
                fontSize: "14px",
              }}
            >
              New Password
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              disabled={passwordChanging}
              style={{
                width: "100%",
                padding: "8px",
                fontSize: "14px",
                border: "1px solid #ddd",
                borderRadius: "4px",
              }}
            />
            <small style={{ color: "#666", fontSize: "12px" }}>
              Minimum 8 characters
            </small>
          </div>

          <div style={{ marginBottom: "15px" }}>
            <label
              style={{
                display: "block",
                marginBottom: "5px",
                fontWeight: "bold",
                fontSize: "14px",
              }}
            >
              Confirm New Password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              disabled={passwordChanging}
              style={{
                width: "100%",
                padding: "8px",
                fontSize: "14px",
                border: "1px solid #ddd",
                borderRadius: "4px",
              }}
            />
          </div>

          <button
            type="submit"
            className="btn btn-success"
            disabled={
              passwordChanging ||
              !currentPassword ||
              !newPassword ||
              !confirmPassword
            }
          >
            {passwordChanging ? "Changing..." : "Change Password"}
          </button>
        </form>
      </div>
    );
  };

  const renderTLSCertificateInfo = () => {
    if (config.TLS_ENABLED !== "true") {
      return null;
    }

    return (
      <div
        style={{
          marginTop: "30px",
          padding: "20px",
          background: "#f8f9fa",
          border: "1px solid #dee2e6",
          borderRadius: "4px",
        }}
      >
        <h3 style={{ marginTop: 0, marginBottom: "15px" }}>
          TLS Certificate Information
        </h3>

        {certLoading && (
          <div className="loading">Loading certificate info...</div>
        )}

        {certError && (
          <div className="alert alert-error" style={{ marginBottom: "15px" }}>
            {certError}
          </div>
        )}

        {certInfo && (
          <div>
            <div style={{ marginBottom: "15px" }}>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "180px 1fr",
                  gap: "10px",
                  fontSize: "14px",
                }}
              >
                <div style={{ fontWeight: "bold" }}>Subject:</div>
                <div style={{ fontFamily: "monospace", fontSize: "13px" }}>
                  {certInfo.subject}
                </div>

                <div style={{ fontWeight: "bold" }}>Issuer:</div>
                <div style={{ fontFamily: "monospace", fontSize: "13px" }}>
                  {certInfo.issuer}
                </div>

                <div style={{ fontWeight: "bold" }}>Valid From:</div>
                <div>{certInfo.valid_from}</div>

                <div style={{ fontWeight: "bold" }}>Valid To:</div>
                <div>{certInfo.valid_to}</div>

                <div style={{ fontWeight: "bold" }}>Days Until Expiry:</div>
                <div
                  style={{
                    color:
                      certInfo.days_until_expiry < 30
                        ? "#e74c3c"
                        : certInfo.days_until_expiry < 90
                        ? "#f39c12"
                        : "#27ae60",
                    fontWeight: "bold",
                  }}
                >
                  {certInfo.days_until_expiry} days
                </div>

                <div style={{ fontWeight: "bold" }}>Self-Signed:</div>
                <div>{certInfo.is_self_signed ? "Yes" : "No"}</div>

                {certInfo.san_dns.length > 0 && (
                  <>
                    <div style={{ fontWeight: "bold" }}>DNS Names:</div>
                    <div>{certInfo.san_dns.join(", ")}</div>
                  </>
                )}

                {certInfo.san_ip.length > 0 && (
                  <>
                    <div style={{ fontWeight: "bold" }}>IP Addresses:</div>
                    <div>{certInfo.san_ip.join(", ")}</div>
                  </>
                )}

                <div style={{ fontWeight: "bold" }}>Fingerprint:</div>
                <div
                  style={{
                    fontFamily: "monospace",
                    fontSize: "11px",
                    wordBreak: "break-all",
                  }}
                >
                  {certInfo.fingerprint}
                </div>
              </div>
            </div>

            {validationMessage && (
              <div
                className={
                  validationMessage.includes("match") &&
                  !validationMessage.includes("do not")
                    ? "alert alert-success"
                    : "alert alert-error"
                }
                style={{ marginBottom: "15px" }}
              >
                {validationMessage}
              </div>
            )}

            <div style={{ display: "flex", gap: "10px" }}>
              <button
                type="button"
                className="btn"
                onClick={loadCertificateInfo}
                disabled={certLoading}
                style={{ background: "#95a5a6" }}
              >
                {certLoading ? "Refreshing..." : "Refresh Info"}
              </button>
            </div>
          </div>
        )}

        {!certLoading && !certInfo && !certError && (
          <button
            type="button"
            className="btn"
            onClick={loadCertificateInfo}
            style={{ background: "#3498db" }}
          >
            Load Certificate Info
          </button>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="card">
        <div className="loading">Loading configuration...</div>
      </div>
    );
  }

  if (!schema) {
    return (
      <div className="card">
        <div className="alert alert-error">
          Failed to load configuration schema
        </div>
      </div>
    );
  }

  // Group fields by section
  const sections: {
    [key: string]: Array<[string, ConfigSchema["properties"][string]]>;
  } = {};

  Object.entries(schema.properties).forEach(([key, props]) => {
    const section = props.section || "Other";
    if (!sections[section]) {
      sections[section] = [];
    }
    sections[section].push([key, props]);
  });

  // Sort sections by first item's order
  const sortedSections = Object.entries(sections).sort((a, b) => {
    const minOrderA = Math.min(...a[1].map(([_, props]) => props.order || 999));
    const minOrderB = Math.min(...b[1].map(([_, props]) => props.order || 999));
    return minOrderA - minOrderB;
  });

  return (
    <div>
      <div className="card">
        <h2 style={{ marginTop: 0 }}>Application Settings</h2>
        <p style={{ color: "#666", marginBottom: "20px" }}>
          Manage configuration for the ISC Web DHCP Manager application. These
          settings are stored in{" "}
          <code>/etc/isc-web-dhcp-manager/config.conf</code>.
        </p>

        {error && <div className="alert alert-error">{error}</div>}
        {successMessage && (
          <div className="alert alert-success">{successMessage}</div>
        )}

        <form onSubmit={handleSubmit}>
          {sortedSections.map(([sectionName, fields]) => (
            <div key={sectionName} style={{ marginBottom: "30px" }}>
              <h3
                style={{
                  marginBottom: "15px",
                  paddingBottom: "8px",
                  borderBottom: "2px solid #3498db",
                  color: "#2c3e50",
                }}
              >
                {sectionName}
              </h3>

              {fields
                .sort((a, b) => (a[1].order || 999) - (b[1].order || 999))
                .map(([key, props]) => renderField(key, props))}
            </div>
          ))}

          <div
            style={{
              display: "flex",
              gap: "10px",
              marginTop: "30px",
              paddingTop: "20px",
              borderTop: "1px solid #ddd",
            }}
          >
            <button
              type="submit"
              className="btn btn-success"
              disabled={saving || !hasChanges}
            >
              {saving ? "Saving..." : "Save Configuration"}
            </button>
            <button
              type="button"
              className="btn"
              onClick={handleReset}
              disabled={saving || !hasChanges}
              style={{ background: "#95a5a6" }}
            >
              Reset
            </button>
          </div>
        </form>

        {renderPasswordChange()}

        {renderTLSCertificateInfo()}

        <div
          style={{
            marginTop: "30px",
            padding: "15px",
            background: "#fff3cd",
            border: "1px solid #ffc107",
            borderRadius: "4px",
            fontSize: "14px",
          }}
        >
          <strong>Important:</strong> Changes to application settings may
          require restarting the backend service to take effect. Read-only
          fields are auto-generated and cannot be modified through this
          interface.
        </div>
      </div>
    </div>
  );
};

export default AppSettingsForm;
