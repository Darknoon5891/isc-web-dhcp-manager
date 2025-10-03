/**
 * API Service Layer for DHCP Configuration Manager
 * Handles all HTTP communication with the Flask backend
 */

export interface DHCPHost {
  hostname: string;
  mac: string;
  ip: string;
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

class APIError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = 'APIError';
  }
}

class APIService {
  private baseURL: string;

  constructor() {
    // In development, requests will be proxied to Flask backend
    this.baseURL = process.env.NODE_ENV === 'production' 
      ? process.env.REACT_APP_API_URL || ''
      : '';
  }

  private async request<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}/api${endpoint}`;
    
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new APIError(
          errorData.message || errorData.error || `HTTP ${response.status}`,
          response.status
        );
      }

      // Handle empty responses (e.g., from DELETE requests)
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        return {} as T;
      }

      return await response.json();
    } catch (error) {
      if (error instanceof APIError) {
        throw error;
      }
      
      // Network or parsing errors
      throw new APIError(
        error instanceof Error ? error.message : 'Network error occurred'
      );
    }
  }

  // Host management endpoints
  async getHosts(): Promise<DHCPHost[]> {
    return this.request<DHCPHost[]>('/hosts');
  }

  async getHost(hostname: string): Promise<DHCPHost> {
    return this.request<DHCPHost>(`/hosts/${encodeURIComponent(hostname)}`);
  }

  async addHost(host: DHCPHost): Promise<DHCPHost> {
    return this.request<DHCPHost>('/hosts', {
      method: 'POST',
      body: JSON.stringify(host),
    });
  }

  async updateHost(hostname: string, updates: Partial<Omit<DHCPHost, 'hostname'>>): Promise<DHCPHost> {
    return this.request<DHCPHost>(`/hosts/${encodeURIComponent(hostname)}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  async deleteHost(hostname: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/hosts/${encodeURIComponent(hostname)}`, {
      method: 'DELETE',
    });
  }

  // Configuration management
  async getConfig(): Promise<{ config: string }> {
    return this.request<{ config: string }>('/config');
  }

  async validateConfig(): Promise<ConfigValidation> {
    return this.request<ConfigValidation>('/validate', {
      method: 'POST',
    });
  }

  // Service management
  async getServiceStatus(): Promise<ServiceStatus> {
    return this.request<ServiceStatus>('/service/status');
  }

  async restartService(): Promise<{ message: string; status: string }> {
    return this.request<{ message: string; status: string }>('/restart', {
      method: 'POST',
    });
  }

  // Backup management
  async getBackups(): Promise<BackupInfo[]> {
    return this.request<BackupInfo[]>('/backups');
  }

  // Utility methods
  async healthCheck(): Promise<DHCPHost[]> {
    return this.request<DHCPHost[]>('/hosts');
  }
}

// Create singleton instance
const apiService = new APIService();

export { APIError };
export default apiService;