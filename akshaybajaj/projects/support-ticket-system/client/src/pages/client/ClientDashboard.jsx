
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import API from "../../services/api";
import Chatbot from "../../components/Chatbot";

const ClientDashboard = () => {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);

  const navigate = useNavigate();

  useEffect(() => {
    const loadTickets = async () => {
      try {
        const { data } = await API.get("/tickets/my");
        setTickets(data);
      } catch (error) {
        console.error("Failed to load tickets:", error);
      } finally {
        setLoading(false);
      }
    };

    loadTickets();
  }, []);

  return (
    <div className="page">
      <div className="dashboard-header">
        <div>
          <span className="eyebrow">CLIENT PORTAL</span>

          <h1>My Tickets</h1>

          <p>
            Track your support requests and their progress.
          </p>
        </div>

        <Link className="primary-link" to="/create-ticket">
          + New Ticket
        </Link>
      </div>

      {loading ? (
        <div className="empty">
          Loading tickets...
        </div>
      ) : tickets.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">🎫</div>

          <h3>No tickets yet</h3>

          <p>
            Create your first support request.
          </p>

          <Link className="primary-link" to="/create-ticket">
            Create Ticket
          </Link>
        </div>
      ) : (
        <div className="ticket-grid">
          {tickets.map((ticket) => (
            <div
              className="ticket-card"
              key={ticket._id}
              onClick={() =>
                navigate(`/ticket/${ticket._id}`)
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
                {ticket.description.length > 120
                  ? `${ticket.description.slice(0, 120)}...`
                  : ticket.description}
              </p>

              <div className="ticket-meta">
                <span>{ticket.department}</span>
                <span>{ticket.status}</span>
              </div>

              <div className="ticket-agent">
                <span>Assigned agent</span>

                <strong>
                  {ticket.assignedAgent?.name ||
                    "Waiting for assignment"}
                </strong>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Customer Support Chatbot */}
      <Chatbot />
    </div>
  );
};

export default ClientDashboard;

