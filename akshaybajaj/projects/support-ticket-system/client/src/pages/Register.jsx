import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import API from "../services/api";
import { useAuth } from "../context/AuthContext";

const Register = () => {
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    role: "client",
    department: "General",
  });

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setForm({
      ...form,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);
      setError("");

      const { data } = await API.post(
        "/auth/register",
        form
      );

      login(data.user, data.token);

      navigate(
        data.user.role === "agent"
          ? "/agent"
          : "/dashboard"
      );
    } catch (error) {
      setError(
        error.response?.data?.message ||
          "Registration failed"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <form className="auth-card" onSubmit={handleSubmit}>
        <div className="brand-icon">S</div>

        <h1>Create account</h1>

        <p className="subtitle">
          Join SupportDesk today
        </p>

        {error && <div className="error">{error}</div>}

        <label>Full name</label>

        <input
          name="name"
          placeholder="Your name"
          value={form.name}
          onChange={handleChange}
          required
        />

        <label>Email</label>

        <input
          type="email"
          name="email"
          placeholder="you@example.com"
          value={form.email}
          onChange={handleChange}
          required
        />

        <label>Password</label>

        <input
          type="password"
          name="password"
          placeholder="Create a password"
          value={form.password}
          onChange={handleChange}
          required
        />

        <label>Account type</label>

        <select
          name="role"
          value={form.role}
          onChange={handleChange}
        >
          <option value="client">Client</option>
          <option value="agent">Support Agent</option>
        </select>

        {form.role === "agent" && (
          <>
            <label>Department</label>

            <select
              name="department"
              value={form.department}
              onChange={handleChange}
            >
              <option value="General">General</option>
              <option value="Technical">Technical</option>
              <option value="Billing">Billing</option>
              <option value="Account">Account</option>
            </select>
          </>
        )}

        <button className="main-button" disabled={loading}>
          {loading ? "Creating..." : "Create account"}
        </button>

        <p className="auth-footer">
          Already have an account?{" "}
          <Link to="/login">Sign in</Link>
        </p>
      </form>
    </div>
  );
};

export default Register;