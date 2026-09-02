import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import API from "../../services/api";

const AgentTicketDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [ticket, setTicket] = useState(null);

  const loadTicket = async () => {
    try {
      const { data } = await API.get(`/tickets/${id}`);
      setTicket(data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    loadTicket();
  }, [id]);

  const changeStatus = async (status) => {
    try {
      await API.patch(`/tickets/${id}/status`, {
        status,
      });

      await loadTicket();
    } catch (error) {
      alert(
        error.response?.data?.message ||
          "Could not update ticket"
      );
    }
  };

  if (!ticket) {
    return <div className="page">Loading...</div>;
  }

  return (
    <div className="page narrow-page">
      <button
        className="back-button"
        onClick={() => navigate("/agent")}
      >
        ← Back to queue
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

        <h3>Customer</h3>

        <div className="agent-box">
          <strong>{ticket.client?.name}</strong>
          <span>{ticket.client?.email}</span>
        </div>

        <h3>Description</h3>

        <p className="description">
          {ticket.description}
        </p>

        <h3>Automatic Triage</h3>

        <div className="triage-box">
          <div>
            <span>Department</span>
            <strong>{ticket.department}</strong>
          </div>

          <div>
            <span>Urgency</span>
            <strong>{ticket.urgency}</strong>
          </div>

          <div>
            <span>Tags</span>

            <div className="tags">
              {ticket.tags.map((tag) => (
                <span key={tag}>#{tag}</span>
              ))}
            </div>
          </div>
        </div>

        <h3>Update Status</h3>

        <div className="status-buttons">
          <button
            className="secondary-button"
            onClick={() => changeStatus("Open")}
          >
            Open
          </button>

          <button
            className="secondary-button"
            onClick={() =>
              changeStatus("In Progress")
            }
          >
            In Progress
          </button>

          <button
            className="success-button"
            onClick={() => changeStatus("Resolved")}
          >
            Resolve
          </button>

          <button
            className="dark-button"
            onClick={() => changeStatus("Closed")}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default AgentTicketDetails;