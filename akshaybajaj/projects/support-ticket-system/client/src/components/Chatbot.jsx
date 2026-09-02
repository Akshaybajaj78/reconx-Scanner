import { useState } from "react";
import API from "../services/api";

export default function Chatbot() {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([
    {
      sender: "bot",
      text: "Hi! 👋 I'm your support assistant. How can I help you today?",
    },
  ]);
  const [loading, setLoading] = useState(false);

  const sendMessage = async (e) => {
    e.preventDefault();

    if (!message.trim() || loading) return;

    const userMessage = message.trim();

    setMessages((prev) => [
      ...prev,
      { sender: "user", text: userMessage },
    ]);

    setMessage("");
    setLoading(true);

    try {
      const response = await API.post("/chatbot", {
        message: userMessage,
      });

      setMessages((prev) => [
        ...prev,
        {
          sender: "bot",
          text: response.data.reply,
        },
      ]);
    } catch (error) {
      console.error("Chatbot error:", error);

      setMessages((prev) => [
        ...prev,
        {
          sender: "bot",
          text: "Sorry, I'm having trouble connecting right now. Please try again.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Floating button */}
      <button
        onClick={() => setOpen(!open)}
        style={{
          position: "fixed",
          bottom: "25px",
          right: "25px",
          width: "60px",
          height: "60px",
          borderRadius: "50%",
          border: "none",
          background: "#2563eb",
          color: "white",
          fontSize: "26px",
          cursor: "pointer",
          boxShadow: "0 5px 20px rgba(0,0,0,0.25)",
          zIndex: 1000,
        }}
      >
        {open ? "✕" : "🤖"}
      </button>

      {/* Chat window */}
      {open && (
        <div
          style={{
            position: "fixed",
            bottom: "95px",
            right: "25px",
            width: "350px",
            height: "500px",
            background: "white",
            borderRadius: "15px",
            boxShadow: "0 10px 40px rgba(0,0,0,0.2)",
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
            zIndex: 999,
            border: "1px solid #e5e7eb",
          }}
        >
          {/* Header */}
          <div
            style={{
              background: "#2563eb",
              color: "white",
              padding: "18px",
              fontWeight: "bold",
              fontSize: "17px",
            }}
          >
            🤖 Support Assistant
            <div
              style={{
                fontSize: "12px",
                fontWeight: "normal",
                opacity: 0.85,
                marginTop: "3px",
              }}
            >
              Online • Ready to help
            </div>
          </div>

          {/* Messages */}
          <div
            style={{
              flex: 1,
              padding: "15px",
              overflowY: "auto",
              background: "#f8fafc",
            }}
          >
            {messages.map((msg, index) => (
              <div
                key={index}
                style={{
                  display: "flex",
                  justifyContent:
                    msg.sender === "user" ? "flex-end" : "flex-start",
                  marginBottom: "10px",
                }}
              >
                <div
                  style={{
                    maxWidth: "80%",
                    padding: "10px 13px",
                    borderRadius: "12px",
                    whiteSpace: "pre-line",
                    background:
                      msg.sender === "user" ? "#2563eb" : "#e5e7eb",
                    color: msg.sender === "user" ? "white" : "#111827",
                  }}
                >
                  {msg.text}
                </div>
              </div>
            ))}

            {loading && (
              <div
                style={{
                  color: "#6b7280",
                  fontSize: "13px",
                }}
              >
                Assistant is typing...
              </div>
            )}
          </div>

          {/* Input */}
          <form
            onSubmit={sendMessage}
            style={{
              display: "flex",
              padding: "10px",
              borderTop: "1px solid #e5e7eb",
              background: "white",
            }}
          >
            <input
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type your message..."
              style={{
                flex: 1,
                border: "1px solid #d1d5db",
                borderRadius: "8px",
                padding: "10px",
                outline: "none",
              }}
            />

            <button
              type="submit"
              disabled={loading}
              style={{
                marginLeft: "8px",
                border: "none",
                borderRadius: "8px",
                padding: "0 15px",
                background: "#2563eb",
                color: "white",
                cursor: "pointer",
              }}
            >
              ➤
            </button>
          </form>
        </div>
      )}
    </>
  );
}