/**
 * GlobalConfigForm Component
 * Form for managing DHCP global configuration settings
 */

import React, { useState, useEffect } from "react";
import apiService, { DHCPGlobalConfig, APIError } from "../services/api";

interface GlobalConfigFormProps {
  refreshTrigger: number;
}

const GlobalConfigForm: React.FC<GlobalConfigFormProps> = ({
  refreshTrigger,
}) => {
  const [formData, setFormData] = useState<DHCPGlobalConfig>({
    default_lease_time: 600,
    max_lease_time: 7200,
    authoritative: false,
    log_facility: null,
    domain_name: null,
    domain_name_servers: null,
    ntp_servers: null,
    time_offset: null,
    ddns_update_style: "none",
    ping_check: false,
    ping_timeout: null,
  });
  const [originalData, setOriginalData] = useState<DHCPGlobalConfig | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [saveMessage, setSaveMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    loadConfig();
  }, [refreshTrigger]);

  const loadConfig = async () => {
    try {
      setLoading(true);
      setErrors({});
      const config = await apiService.getGlobalConfig();
      setFormData(config);
      setOriginalData(config);
    } catch (err) {
      if (err instanceof APIError) {
        setErrors({ submit: `Failed to load configuration: ${err.message}` });
      } else {
        setErrors({
          submit: "Failed to load configuration. Please check your connection.",
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const validateIP = (ip: string): boolean => {
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    return parts.every((part) => {
      const num = parseInt(part, 10);
      return !isNaN(num) && num >= 0 && num <= 255;
    });
  };

  const validateForm = (): boolean => {
    const newErrors: { [key: string]: string } = {};

    // Lease time validation
    if (formData.default_lease_time <= 0) {
      newErrors.default_lease_time = "Default lease time must be positive";
    }

    if (formData.max_lease_time <= 0) {
      newErrors.max_lease_time = "Max lease time must be positive";
    }

    if (formData.max_lease_time < formData.default_lease_time) {
      newErrors.max_lease_time =
        "Max lease time must be greater than or equal to default lease time";
    }

    // Domain name validation (basic)
    if (formData.domain_name && formData.domain_name.trim()) {
      if (!/^[a-z0-9.-]+$/i.test(formData.domain_name)) {
        newErrors.domain_name = "Invalid domain name format";
      }
    }

    // DNS servers validation
    if (formData.domain_name_servers && formData.domain_name_servers.trim()) {
      const dnsList = formData.domain_name_servers
        .split(",")
        .map((s) => s.trim());
      for (const dns of dnsList) {
        if (!validateIP(dns)) {
          newErrors.domain_name_servers =
            "Invalid DNS server IP (use comma-separated IPs)";
          break;
        }
      }
    }

    // NTP servers validation
    if (formData.ntp_servers && formData.ntp_servers.trim()) {
      const ntpList = formData.ntp_servers.split(",").map((s) => s.trim());
      for (const ntp of ntpList) {
        if (!validateIP(ntp)) {
          newErrors.ntp_servers =
            "Invalid NTP server IP (use comma-separated IPs)";
          break;
        }
      }
    }

    // Ping timeout validation
    if (
      formData.ping_check &&
      formData.ping_timeout !== null &&
      formData.ping_timeout !== undefined &&
      formData.ping_timeout <= 0
    ) {
      newErrors.ping_timeout = "Ping timeout must be positive";
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
      setSaving(true);
      setSaveMessage(null);

      await apiService.updateGlobalConfig(formData);
      const updatedConfig = await apiService.getGlobalConfig();
      setFormData(updatedConfig);
      setOriginalData(updatedConfig);
      setSaveMessage({
        type: "success",
        text: "Global configuration saved successfully!",
      });
    } catch (err) {
      if (err instanceof APIError) {
        setSaveMessage({ type: "error", text: err.message });
      } else {
        setSaveMessage({
          type: "error",
          text: "Failed to save configuration. Please try again.",
        });
      }
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    if (originalData) {
      setFormData(originalData);
      setErrors({});
      setSaveMessage(null);
    }
  };

  const handleChange = (field: keyof DHCPGlobalConfig, value: any) => {
    setFormData({ ...formData, [field]: value });
    if (errors[field]) {
      setErrors({ ...errors, [field]: "" });
    }
    setSaveMessage(null);
  };

  if (loading) {
    return (
      <div className="card">
        <div className="loading">Loading global configuration...</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Global DHCP Configuration</h2>

      {saveMessage && (
        <div
          className={`alert ${
            saveMessage.type === "success" ? "alert-success" : "alert-error"
          }`}
          style={{ marginBottom: "20px" }}
        >
          {saveMessage.text}
        </div>
      )}

      {errors.submit && (
        <div className="alert alert-error" style={{ marginBottom: "20px" }}>
          {errors.submit}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Lease Times Section */}
        <h3
          style={{
            marginBottom: "15px",
            fontSize: "18px",
            borderBottom: "2px solid #3498db",
            paddingBottom: "8px",
          }}
        >
          Lease Times
        </h3>

        <div className="form-group">
          <label htmlFor="default_lease_time">
            Default Lease Time (seconds){" "}
            <span style={{ color: "#e74c3c" }}>*</span>
          </label>
          <input
            id="default_lease_time"
            type="number"
            value={formData.default_lease_time}
            onChange={(e) =>
              handleChange("default_lease_time", parseInt(e.target.value) || 0)
            }
            className={errors.default_lease_time ? "error" : ""}
          />
          {errors.default_lease_time && (
            <span className="error-message">{errors.default_lease_time}</span>
          )}
          <small style={{ color: "#666" }}>
            Default: 600 seconds (10 minutes)
          </small>
        </div>

        <div className="form-group">
          <label htmlFor="max_lease_time">
            Maximum Lease Time (seconds){" "}
            <span style={{ color: "#e74c3c" }}>*</span>
          </label>
          <input
            id="max_lease_time"
            type="number"
            value={formData.max_lease_time}
            onChange={(e) =>
              handleChange("max_lease_time", parseInt(e.target.value) || 0)
            }
            className={errors.max_lease_time ? "error" : ""}
          />
          {errors.max_lease_time && (
            <span className="error-message">{errors.max_lease_time}</span>
          )}
          <small style={{ color: "#666" }}>
            Default: 7200 seconds (2 hours)
          </small>
        </div>

        {/* Server Behavior Section */}
        <h3
          style={{
            marginTop: "30px",
            marginBottom: "15px",
            fontSize: "18px",
            borderBottom: "2px solid #3498db",
            paddingBottom: "8px",
          }}
        >
          Server Behavior
        </h3>

        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={formData.authoritative}
              onChange={(e) => handleChange("authoritative", e.target.checked)}
              style={{ marginRight: "10px", width: "auto" }}
            />
            Authoritative Server
          </label>
          <small
            style={{ color: "#666", display: "block", marginLeft: "30px" }}
          >
            Enable if this DHCP server is authoritative for the subnets it
            serves
          </small>
        </div>

        <div className="form-group">
          <label htmlFor="log_facility">Log Facility</label>
          <select
            id="log_facility"
            value={formData.log_facility || ""}
            onChange={(e) =>
              handleChange("log_facility", e.target.value || null)
            }
          >
            <option value="">None (default)</option>
            <option value="daemon">daemon</option>
            <option value="local0">local0</option>
            <option value="local1">local1</option>
            <option value="local2">local2</option>
            <option value="local3">local3</option>
            <option value="local4">local4</option>
            <option value="local5">local5</option>
            <option value="local6">local6</option>
            <option value="local7">local7</option>
          </select>
          <small style={{ color: "#666" }}>
            Syslog facility for DHCP server logging
          </small>
        </div>

        {/* Global DHCP Options Section */}
        <h3
          style={{
            marginTop: "30px",
            marginBottom: "15px",
            fontSize: "18px",
            borderBottom: "2px solid #3498db",
            paddingBottom: "8px",
          }}
        >
          Global DHCP Options
        </h3>

        <div className="form-group">
          <label htmlFor="domain_name">Domain Name</label>
          <input
            id="domain_name"
            type="text"
            value={formData.domain_name || ""}
            onChange={(e) =>
              handleChange("domain_name", e.target.value || null)
            }
            placeholder="example.com"
            className={errors.domain_name ? "error" : ""}
          />
          {errors.domain_name && (
            <span className="error-message">{errors.domain_name}</span>
          )}
          <small style={{ color: "#666" }}>
            Domain name provided to DHCP clients
          </small>
        </div>

        <div className="form-group">
          <label htmlFor="domain_name_servers">
            DNS Servers (comma-separated)
          </label>
          <input
            id="domain_name_servers"
            type="text"
            value={formData.domain_name_servers || ""}
            onChange={(e) =>
              handleChange("domain_name_servers", e.target.value || null)
            }
            placeholder="8.8.8.8, 8.8.4.4"
            className={errors.domain_name_servers ? "error" : ""}
          />
          {errors.domain_name_servers && (
            <span className="error-message">{errors.domain_name_servers}</span>
          )}
          <small style={{ color: "#666" }}>
            DNS servers provided to DHCP clients
          </small>
        </div>

        <div className="form-group">
          <label htmlFor="ntp_servers">
            NTP Servers (comma-separated, optional)
          </label>
          <input
            id="ntp_servers"
            type="text"
            value={formData.ntp_servers || ""}
            onChange={(e) =>
              handleChange("ntp_servers", e.target.value || null)
            }
            placeholder="e.g. 132.163.96.6 (time.nist.gov)"
            className={errors.ntp_servers ? "error" : ""}
          />
          {errors.ntp_servers && (
            <span className="error-message">{errors.ntp_servers}</span>
          )}
          <small style={{ color: "#666" }}>
            NTP servers provided to DHCP clients (optional)
          </small>
        </div>

        <div className="form-group">
          <label htmlFor="time_offset">
            Time Offset (seconds from UTC, optional)
          </label>
          <input
            id="time_offset"
            type="number"
            value={formData.time_offset !== null ? formData.time_offset : ""}
            onChange={(e) =>
              handleChange(
                "time_offset",
                e.target.value ? parseInt(e.target.value) : null
              )
            }
            placeholder="0"
          />
          <small style={{ color: "#666" }}>
            Offset from UTC in seconds (can be negative)
          </small>
        </div>

        {/* Advanced Section */}
        <div style={{ marginTop: "30px" }}>
          <button
            type="button"
            className="btn"
            onClick={() => setShowAdvanced(!showAdvanced)}
            style={{ marginBottom: "15px" }}
          >
            {showAdvanced ? "▼" : "▶"} Advanced Settings
          </button>

          {showAdvanced && (
            <div
              style={{ paddingLeft: "20px", borderLeft: "3px solid #95a5a6" }}
            >
              <div className="form-group">
                <label htmlFor="ddns_update_style">DDNS Update Style</label>
                <select
                  id="ddns_update_style"
                  value={formData.ddns_update_style}
                  onChange={(e) =>
                    handleChange("ddns_update_style", e.target.value)
                  }
                >
                  <option value="none">None</option>
                  <option value="interim">Interim</option>
                  <option value="ad-hoc">Ad-hoc</option>
                </select>
                <small
                  style={{
                    color: "#e67e22",
                    display: "block",
                    marginTop: "5px",
                  }}
                >
                  <strong>Note:</strong> Full DDNS configuration requires manual
                  editing of zone declarations in the PTR Zones tab
                </small>
              </div>

              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={formData.ping_check}
                    onChange={(e) =>
                      handleChange("ping_check", e.target.checked)
                    }
                    style={{ marginRight: "10px", width: "auto" }}
                  />
                  Ping Check Before Assignment
                </label>
                <small
                  style={{
                    color: "#666",
                    display: "block",
                    marginLeft: "30px",
                  }}
                >
                  Ping IP addresses before assigning them to verify they're not
                  in use
                </small>
              </div>

              {formData.ping_check && (
                <div className="form-group">
                  <label htmlFor="ping_timeout">Ping Timeout (seconds)</label>
                  <input
                    id="ping_timeout"
                    type="number"
                    value={
                      formData.ping_timeout !== null
                        ? formData.ping_timeout
                        : ""
                    }
                    onChange={(e) =>
                      handleChange(
                        "ping_timeout",
                        e.target.value ? parseInt(e.target.value) : null
                      )
                    }
                    placeholder="1"
                    className={errors.ping_timeout ? "error" : ""}
                  />
                  {errors.ping_timeout && (
                    <span className="error-message">{errors.ping_timeout}</span>
                  )}
                  <small style={{ color: "#666" }}>
                    How long to wait for ping response (default: 1 second)
                  </small>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div
          className="form-actions"
          style={{ marginTop: "30px", display: "flex", gap: "10px" }}
        >
          <button type="submit" className="btn btn-success" disabled={saving}>
            {saving ? "Saving..." : "Save Configuration"}
          </button>
          <button
            type="button"
            className="btn"
            onClick={handleReset}
            disabled={saving}
          >
            Reset to Current
          </button>
        </div>

        <div
          style={{
            marginTop: "20px",
            padding: "15px",
            backgroundColor: "#fff3cd",
            borderRadius: "4px",
            color: "#000",
            border: "1px solid #ffc107",
          }}
        >
          <strong>Important:</strong> After saving global configuration,
          remember to:
          <ul
            style={{
              marginTop: "10px",
              marginBottom: "0",
              paddingLeft: "20px",
            }}
          >
            <li>Validate the configuration in the Configuration tab</li>
            <li>Restart the DHCP service to apply changes</li>
          </ul>
        </div>
      </form>
    </div>
  );
};

export default GlobalConfigForm;
