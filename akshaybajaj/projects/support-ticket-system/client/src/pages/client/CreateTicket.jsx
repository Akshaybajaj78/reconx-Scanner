import { useState } from "react";
import { useNavigate } from "react-router-dom";

import API from "../../services/api";

const CreateTicket = () => {
  const navigate = useNavigate();

  const [subject, setSubject] = useState("");
  const [description, setDescription] = useState("");
  const [attachment, setAttachment] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    const formData = new FormData();

    formData.append("subject", subject);
    formData.append("description", description);

    if (attachment) {
      formData.append("attachment", attachment);
    }

    try {
      setLoading(true);

      const { data } = await API.post(
        "/tickets",
        formData
      );

      alert(data.message);

      navigate("/dashboard");
    } catch (error) {
      alert(
        error.response?.data?.message ||
          "Could not create ticket"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page narrow-page">
      <div className="form-card">
        <span className="eyebrow">SUPPORT REQUEST</span>

        <h1>Create a Ticket</h1>

        <p className="form-description">
          Tell us what's happening and our system will
          automatically route your request to the right team.
        </p>

        <form onSubmit={handleSubmit}>
          <label>Subject</label>

          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="Example: Payment deducted but order failed"
            required
          />

          <label>Description</label>

          <textarea
            rows="8"
            value={description}
            onChange={(e) =>
              setDescription(e.target.value)
            }
            placeholder="Describe your issue in detail..."
            required
          />

          <label>Attachment</label>

          <div className="file-input">
            <input
              type="file"
              onChange={(e) =>
                setAttachment(e.target.files[0])
              }
            />
          </div>

          <div className="form-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={() => navigate("/dashboard")}
            >
              Cancel
            </button>

            <button
              className="main-button"
              disabled={loading}
            >
              {loading
                ? "Submitting..."
                : "Submit Ticket"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateTicket;