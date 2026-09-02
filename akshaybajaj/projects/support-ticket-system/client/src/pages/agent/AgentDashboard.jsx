import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import API from "../../services/api";

const AgentDashboard = () => {
  const [tickets, setTickets] = useState([]);
  const [stats, setStats] = useState({});
  const [urgency, setUrgency] = useState("");

  const navigate = useNavigate();

  const loadData = async () => {
    try {
      const url = urgency
        ? `/tickets/assigned?urgency=${urgency}`
        : "/tickets/assigned";

      const [ticketsResponse, statsResponse] =
        await Promise.all([
          API.get(url),
          API.get("/tickets/stats"),
        ]);

      setTickets(ticketsResponse.data);
      setStats(statsResponse.data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    loadData();
  }, [urgency]);

  return (
    <div className="page">
      <div className="dashboard-header">
        <div>
          <span className="eyebrow">AGENT PORTAL</span>
          <h1>Support Queue</h1>
          <p>Manage and resolve customer requests.</p>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat">
          <span>Total</span>
          <strong>{stats.total || 0}</strong>
        </div>

        <div className="stat">
          <span>Open</span>
          <strong>{stats.open || 0}</strong>
        </div>

        <div className="stat">
          <span>In Progress</span>
          <strong>{stats.inProgress || 0}</strong>
        </div>

        <div className="stat">
          <span>Resolved</span>
          <strong>{stats.resolved || 0}</strong>
        </div>

        <div className="stat critical-stat">
          <span>Critical</span>
          <strong>{stats.critical || 0}</strong>
        </div>
      </div>

      <div className="queue-header">
        <h2>Assigned Tickets</h2>

        <select
          value={urgency}
          onChange={(e) => setUrgency(e.target.value)}
        >
          <option value="">All priorities</option>
          <option value="Low">Low</option>
          <option value="Medium">Medium</option>
          <option value="High">High</option>
          <option value="Critical">Critical</option>
        </select>
      </div>

      {tickets.length === 0 ? (
        <div className="empty">
          <h3>No assigned tickets</h3>
          <p>Your queue is clear. 🎉</p>
        </div>
      ) : (
        <div className="ticket-grid">
          {tickets.map((ticket) => (
            <div
              className="ticket-card"
              key={ticket._id}
              onClick={() =>
                navigate(`/agent/ticket/${ticket._id}`)
              }
            >
              <div className="ticket-top">
                <span className="ticket-id">
                  #{ticket._id.slice(-6).toUpperCase()}
                </span>

                <span
                  className={`priority ${ticket.urgency.toLowerCase()}`}
                >
                  {ticket.urgency}
                </span>
              </div>

              <h3>{ticket.subject}</h3>

              <p>
                {ticket.description.slice(0, 120)}
                {ticket.description.length > 120
                  ? "..."
                  : ""}
              </p>

              <div className="ticket-meta">
                <span>{ticket.department}</span>
                <span>{ticket.status}</span>
              </div>

              <div className="ticket-agent">
                <span>Customer</span>
                <strong>
                  {ticket.client?.name || "Unknown"}
                </strong>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AgentDashboard;