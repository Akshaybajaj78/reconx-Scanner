import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import API from "../services/api";
import { useAuth } from "../context/AuthContext";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const submitHandler = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);
      setError("");

      const { data } = await API.post("/auth/login", {
        email,
        password,
      });

      login(data.user, data.token);

      navigate(
        data.user.role === "agent"
          ? "/agent"
          : "/dashboard"
      );
    } catch (error) {
      setError(
        error.response?.data?.message ||
          "Login failed"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <form className="auth-card" onSubmit={submitHandler}>
        <div className="brand-icon">S</div>

        <h1>Welcome back</h1>

        <p className="subtitle">
          Sign in to your SupportDesk account
        </p>

        {error && <div className="error">{error}</div>}

        <label>Email</label>

        <input
          type="email"
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />

        <label>Password</label>

        <input
          type="password"
          placeholder="••••••••"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        <button className="main-button" disabled={loading}>
          {loading ? "Signing in..." : "Sign in"}
        </button>

        <p className="auth-footer">
          Don't have an account?{" "}
          <Link to="/register">Create one</Link>
        </p>
      </form>
    </div>
  );
};

export default Login;