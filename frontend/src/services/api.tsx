/**
 * API Service Layer for ISC Web DHCP Configuration Manager
 * Handles all HTTP communication with the Flask backend
 */

export interface DHCPHost {
  hostname: string;
  mac: string;
  ip: string;
}

export interface DHCPSubnet {
  network: string;
  netmask: string;
  range_start?: string;
  range_end?: string;
  options?: { [key: string]: string };
}

export interface DHCPZone {
  zone_name: string;
  primary: string;
  key_name?: string;
  secondary?: string[];
}

export interface DHCPLease {
  ip: string;
  mac: string;
  starts: string;
  ends: string;
  state: string;
  hostname?: string;
  binding_state: string;
}

export interface DHCPGlobalConfig {
  default_lease_time: number;
  max_lease_time: number;
  authoritative: boolean;
  log_facility?: string | null;
  domain_name?: string | null;
  domain_name_servers?: string | null;
  ntp_servers?: string | null;
  time_offset?: number | null;
  ddns_update_style: string;
  ping_check: boolean;
  ping_timeout?: number | null;
}

export interface APIResponse<T> {
  data?: T;
  error?: string;
  message?: string;
}

export interface ServiceStatus {
  service: string;
  status: string;
  active: boolean;
  details: string;
}

export interface ConfigValidation {
  valid: boolean;
  message: string;
}

export interface BackupInfo {
  filename: string;
  timestamp: number;
  size: number;
}

export interface TLSCertificateInfo {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  days_until_expiry: number;
  san_dns: string[];
  san_ip: string[];
  fingerprint: string;
  is_self_signed: boolean;
}

export interface TLSValidationResult {
  valid: boolean;
  message: string;
}

export interface NginxReloadResult {
  success: boolean;
  message: string;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
}

export interface VerifyResponse {
  valid: boolean;
}

class APIError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = "APIError";
  }
}

class APIService {
  private baseURL: string;

  constructor() {
    // In development, requests will be proxied to Flask backend
    this.baseURL =
      process.env.NODE_ENV === "production"
        ? process.env.REACT_APP_API_URL || ""
        : "";
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}/api${endpoint}`;

    // Get token from localStorage
    const token = localStorage.getItem("auth_token");

    const config: RequestInit = {
      headers: {
        "Content-Type": "application/json",
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);

      if (!response.ok) {
        // Handle 401 Unauthorized - clear token and trigger re-login
        // Skip reload for login endpoint to allow error message to be displayed
        if (response.status === 401 && !endpoint.includes("/auth/login")) {
          localStorage.removeItem("auth_token");
          // Reload page to show login screen
          window.location.reload();
        }

        const errorData = await response.json().catch(() => ({}));
        throw new APIError(
          errorData.message || errorData.error || `HTTP ${response.status}`,
          response.status
        );
      }

      // Handle empty responses (e.g., from DELETE requests)
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        return {} as T;
      }

      return await response.json();
    } catch (error) {
      if (error instanceof APIError) {
        throw error;
      }

      // Network or parsing errors
      throw new APIError(
        error instanceof Error ? error.message : "Network error occurred"
      );
    }
  }

  // Host management endpoints
  async getHosts(): Promise<DHCPHost[]> {
    return this.request<DHCPHost[]>("/hosts");
  }

  async getHost(hostname: string): Promise<DHCPHost> {
    return this.request<DHCPHost>(`/hosts/${encodeURIComponent(hostname)}`);
  }

  async addHost(host: DHCPHost): Promise<DHCPHost> {
    return this.request<DHCPHost>("/hosts", {
      method: "POST",
      body: JSON.stringify(host),
    });
  }

  async updateHost(
    hostname: string,
    updates: Partial<Omit<DHCPHost, "hostname">>
  ): Promise<DHCPHost> {
    return this.request<DHCPHost>(`/hosts/${encodeURIComponent(hostname)}`, {
      method: "PUT",
      body: JSON.stringify(updates),
    });
  }

  async deleteHost(hostname: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      `/hosts/${encodeURIComponent(hostname)}`,
      {
        method: "DELETE",
      }
    );
  }

  // Configuration management
  async getConfig(): Promise<{ config: string }> {
    return this.request<{ config: string }>("/config");
  }

  async validateConfig(): Promise<ConfigValidation> {
    return this.request<ConfigValidation>("/validate", {
      method: "POST",
    });
  }

  // Service management
  async getServiceStatus(serviceName: string = "isc-dhcp-server"): Promise<ServiceStatus> {
    return this.request<ServiceStatus>(`/service/status/${serviceName}`);
  }

  async restartService(serviceName: string = "isc-dhcp-server"): Promise<{ message: string; status: string }> {
    return this.request<{ message: string; status: string }>(`/restart/${serviceName}`, {
      method: "POST",
    });
  }

  // Backup management
  async getBackups(): Promise<BackupInfo[]> {
    return this.request<BackupInfo[]>("/backups");
  }

  // Subnet management endpoints
  async getSubnets(): Promise<DHCPSubnet[]> {
    return this.request<DHCPSubnet[]>("/subnets");
  }

  async getSubnet(network: string): Promise<DHCPSubnet> {
    return this.request<DHCPSubnet>(`/subnets/${encodeURIComponent(network)}`);
  }

  async addSubnet(subnet: DHCPSubnet): Promise<DHCPSubnet> {
    return this.request<DHCPSubnet>("/subnets", {
      method: "POST",
      body: JSON.stringify(subnet),
    });
  }

  async updateSubnet(
    network: string,
    updates: Partial<Omit<DHCPSubnet, "network">>
  ): Promise<DHCPSubnet> {
    return this.request<DHCPSubnet>(`/subnets/${encodeURIComponent(network)}`, {
      method: "PUT",
      body: JSON.stringify(updates),
    });
  }

  async deleteSubnet(network: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      `/subnets/${encodeURIComponent(network)}`,
      {
        method: "DELETE",
      }
    );
  }

  // Zone management endpoints
  async getZones(): Promise<DHCPZone[]> {
    return this.request<DHCPZone[]>("/zones");
  }

  async getZone(zone_name: string): Promise<DHCPZone> {
    return this.request<DHCPZone>(`/zones/${encodeURIComponent(zone_name)}`);
  }

  async addZone(zone: DHCPZone): Promise<DHCPZone> {
    return this.request<DHCPZone>("/zones", {
      method: "POST",
      body: JSON.stringify(zone),
    });
  }

  async updateZone(
    zone_name: string,
    updates: Partial<Omit<DHCPZone, "zone_name">>
  ): Promise<DHCPZone> {
    return this.request<DHCPZone>(`/zones/${encodeURIComponent(zone_name)}`, {
      method: "PUT",
      body: JSON.stringify(updates),
    });
  }

  async deleteZone(zone_name: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(
      `/zones/${encodeURIComponent(zone_name)}`,
      {
        method: "DELETE",
      }
    );
  }

  // Lease viewing endpoints
  async getLeases(): Promise<DHCPLease[]> {
    return this.request<DHCPLease[]>("/leases");
  }

  async getActiveLeases(): Promise<DHCPLease[]> {
    return this.request<DHCPLease[]>("/leases/active");
  }

  // Global configuration endpoints
  async getGlobalConfig(): Promise<DHCPGlobalConfig> {
    return this.request<DHCPGlobalConfig>("/global-config");
  }

  async updateGlobalConfig(
    config: DHCPGlobalConfig
  ): Promise<DHCPGlobalConfig> {
    return this.request<DHCPGlobalConfig>("/global-config", {
      method: "PUT",
      body: JSON.stringify(config),
    });
  }

  // System endpoints
  async getSystemHostname(): Promise<{ hostname: string }> {
    return this.request<{ hostname: string }>("/system/hostname");
  }

  // App configuration endpoints
  async getAppConfig(): Promise<{ [key: string]: string }> {
    return this.request<{ [key: string]: string }>("/app-config");
  }

  async getAppConfigSchema(): Promise<any> {
    return this.request<any>("/app-config/schema");
  }

  async updateAppConfig(config: { [key: string]: string }): Promise<{ [key: string]: string }> {
    return this.request<{ [key: string]: string }>("/app-config", {
      method: "PUT",
      body: JSON.stringify(config),
    });
  }

  // TLS certificate management endpoints
  async getTLSCertificateInfo(): Promise<TLSCertificateInfo> {
    return this.request<TLSCertificateInfo>("/tls/certificate-info");
  }

  async validateTLSCertificate(cert_path?: string): Promise<TLSValidationResult> {
    return this.request<TLSValidationResult>("/tls/validate-certificate", {
      method: "POST",
      body: JSON.stringify({ cert_path }),
    });
  }

  // Authentication endpoints
  async login(password: string): Promise<LoginResponse> {
    return this.request<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
  }

  async verifyToken(): Promise<VerifyResponse> {
    return this.request<VerifyResponse>("/auth/verify", {
      method: "POST",
    });
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
    return this.request<{ message: string }>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
  }

  logout(): void {
    localStorage.removeItem("auth_token");
    window.location.reload();
  }

  // Utility methods
  async healthCheck(): Promise<DHCPHost[]> {
    return this.request<DHCPHost[]>("/hosts");
  }
}

// Create singleton instance
const apiService = new APIService();

export { APIError };
export default apiService;
