import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
    },

    role: {
      type: String,
      enum: ["client", "agent"],
      default: "client",
    },

    department: {
      type: String,
      enum: ["Technical", "Billing", "Account", "General"],
      default: "General",
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("User", userSchema);