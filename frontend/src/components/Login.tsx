/**
 * Login Component
 * Authentication interface for ISC Web DHCP Manager
 */

import React, { useState } from "react";
import apiService, { APIError } from "../services/api";

interface LoginProps {
  onLoginSuccess: (token: string) => void;
}

const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!password) {
      setError("Password is required");
      return;
    }

    try {
      setIsLoading(true);
      const response = await apiService.login(password);
      onLoginSuccess(response.token);
    } catch (err) {
      if (err instanceof APIError) {
        setError(err.message);
      } else {
        setError("Login failed. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        backgroundColor: "#f5f5f5",
      }}
    >
      <div
        className="card"
        style={{
          width: "100%",
          maxWidth: "400px",
          padding: "40px",
        }}
      >
        <h1
          style={{
            marginTop: 0,
            marginBottom: "10px",
            textAlign: "center",
            color: "#2c3e50",
          }}
        >
          ISC DHCP Manager
        </h1>
        <p
          style={{
            textAlign: "center",
            color: "#666",
            marginBottom: "30px",
            fontSize: "14px",
          }}
        >
          Please enter your password to continue
        </p>

        {error && (
          <div className="alert alert-error" style={{ marginBottom: "20px" }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: "20px" }}>
            <label
              htmlFor="password"
              style={{
                display: "block",
                marginBottom: "8px",
                fontWeight: "bold",
                fontSize: "14px",
                color: "#2c3e50",
              }}
            >
              Password
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLoading}
              autoFocus
              style={{
                width: "100%",
                padding: "12px",
                fontSize: "14px",
                border: "1px solid #ddd",
                borderRadius: "4px",
                boxSizing: "border-box",
              }}
              placeholder="Enter your password"
            />
          </div>

          <button
            type="submit"
            className="btn btn-success"
            disabled={isLoading || !password}
            style={{
              width: "100%",
              padding: "12px",
              fontSize: "16px",
            }}
          >
            {isLoading ? "Logging in..." : "Login"}
          </button>
        </form>

        <div
          style={{
            marginTop: "30px",
            padding: "15px",
            background: "#fff3cd",
            border: "1px solid #ffc107",
            borderRadius: "4px",
            fontSize: "13px",
          }}
        >
          <strong>Note:</strong> If you've forgotten your password, you can
          regenerate it by re-running the deployment script on the server.
        </div>
      </div>
    </div>
  );
};

export default Login;
