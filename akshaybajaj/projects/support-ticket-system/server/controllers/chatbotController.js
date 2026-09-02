import Ticket from "../models/Ticket.js";

export const chatbot = async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({
        message: "Please enter a message.",
      });
    }

    const text = message.toLowerCase();

    // Greeting
    if (
      text.includes("hello") ||
      text.includes("hi") ||
      text.includes("hey")
    ) {
      return res.json({
        reply:
          "Hi! 👋 I'm your support assistant. I can help you create a ticket, check your ticket status, or answer basic support questions.",
      });
    }

    // Ticket status
    if (
      text.includes("status") ||
      text.includes("my ticket") ||
      text.includes("tickets")
    ) {
      const tickets = await Ticket.find({
        client: req.user._id,
      })
        .sort({ createdAt: -1 })
        .limit(5);

      if (tickets.length === 0) {
        return res.json({
          reply:
            "You don't have any support tickets yet. Would you like me to help you create one? 🎫",
        });
      }

      const ticketList = tickets
        .map(
          (ticket) =>
            `• ${ticket.subject} — ${ticket.status} (${ticket.urgency})`
        )
        .join("\n");

      return res.json({
        reply: `Here are your recent tickets:\n\n${ticketList}`,
      });
    }

    // Create ticket intent
    if (
      text.includes("create ticket") ||
      text.includes("raise ticket") ||
      text.includes("open ticket") ||
      text.includes("complaint")
    ) {
      return res.json({
        reply:
          "Sure! 🎫 Please use the **Create Ticket** option to submit your issue. Our system will automatically determine the department, urgency, tags, and assign an agent.",
      });
    }

    // Password/account
    if (
      text.includes("password") ||
      text.includes("login") ||
      text.includes("account")
    ) {
      return res.json({
        reply:
          "For login or account problems, please create a support ticket under the Account department. 🔐",
      });
    }

    // Billing
    if (
      text.includes("payment") ||
      text.includes("billing") ||
      text.includes("refund")
    ) {
      return res.json({
        reply:
          "For payment, billing, or refund issues, please create a ticket. Our system will route it to the Billing department. 💳",
      });
    }

    // Technical
    if (
      text.includes("error") ||
      text.includes("bug") ||
      text.includes("not working") ||
      text.includes("technical")
    ) {
      return res.json({
        reply:
          "That sounds like a technical issue. 💻 Please create a support ticket with as much detail as possible so our technical team can investigate it.",
      });
    }

    // Default
    return res.json({
      reply:
        "I'm here to help! 🤖 You can ask me about your ticket status, account problems, billing issues, technical problems, or creating a support ticket.",
    });
  } catch (error) {
    console.error("Chatbot error:", error);

    res.status(500).json({
      message: "Chatbot is temporarily unavailable.",
    });
  }
};