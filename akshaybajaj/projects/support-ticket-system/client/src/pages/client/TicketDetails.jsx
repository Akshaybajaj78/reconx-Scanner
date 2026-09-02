import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";

import API from "../../services/api";

const TicketDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [ticket, setTicket] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadTicket = async () => {
      try {
        const { data } = await API.get(`/tickets/${id}`);
        setTicket(data);
      } catch (error) {
        setError(
          error.response?.data?.message ||
            "Could not load ticket"
        );
      }
    };

    loadTicket();
  }, [id]);

  if (error) {
    return (
      <div className="page">
        <div className="error">{error}</div>
      </div>
    );
  }

  if (!ticket) {
    return <div className="page">Loading...</div>;
  }

  return (
    <div className="page narrow-page">
      <button
        className="back-button"
        onClick={() => navigate("/dashboard")}
      >
        ← Back to tickets
      </button>

      <div className="detail-card">
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

        <h1>{ticket.subject}</h1>

        <div className="detail-row">
          <span>{ticket.department}</span>
          <span>{ticket.status}</span>
        </div>

        <hr />

        <h3>Description</h3>
        <p className="description">
          {ticket.description}
        </p>

        <h3>Automatic Classification</h3>

        <div className="tags">
          {ticket.tags.map((tag) => (
            <span key={tag}>#{tag}</span>
          ))}
        </div>

        <h3>Assigned Agent</h3>

        <div className="agent-box">
          {ticket.assignedAgent ? (
            <>
              <strong>
                {ticket.assignedAgent.name}
              </strong>

              <span>
                {ticket.assignedAgent.department} Support
              </span>
            </>
          ) : (
            <span>Waiting for assignment</span>
          )}
        </div>

        <small>
          Created{" "}
          {new Date(ticket.createdAt).toLocaleString()}
        </small>
      </div>
    </div>
  );
};

export default TicketDetails;