import mongoose from "mongoose";

const ticketSchema = new mongoose.Schema(
  {
    subject: {
      type: String,
      required: true,
      trim: true,
    },

    description: {
      type: String,
      required: true,
    },

    attachment: {
      type: String,
      default: null,
    },

    urgency: {
      type: String,
      enum: ["Low", "Medium", "High", "Critical"],
      default: "Low",
    },

    department: {
      type: String,
      enum: ["Technical", "Billing", "Account", "General"],
      default: "General",
    },

    tags: [
      {
        type: String,
      },
    ],

    status: {
      type: String,
      enum: ["Open", "In Progress", "Resolved", "Closed"],
      default: "Open",
    },

    client: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    assignedAgent: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Ticket", ticketSchema);