/**
 * AppSettingsForm Component
 * Manages application configuration settings from /etc/isc-web-dhcp-manager/config.conf
 */

import React, { useState, useEffect } from "react";
import apiService, { APIError } from "../services/api";

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

  const renderField = (key: string, props: ConfigSchema["properties"][string]) => {
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
  const sections: { [key: string]: Array<[string, ConfigSchema["properties"][string]]> } = {};

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
          settings are stored in <code>/etc/isc-web-dhcp-manager/config.conf</code>.
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
