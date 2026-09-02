import express from "express";
import cors from "cors";
import dotenv from "dotenv";

import connectDB from "./config/db.js";

import authRoutes from "./routes/authRoutes.js";
import ticketRoutes from "./routes/ticketRoutes.js";
import chatbotRoutes from "./routes/chatbotRoutes.js";

import errorMiddleware from "./middleware/errorMiddleware.js";

dotenv.config();

connectDB();

const app = express();

app.use(cors());

app.use(express.json());

app.use(express.urlencoded({
  extended: true,
}));

app.use("/uploads", express.static("uploads"));
app.use("/api/chatbot", chatbotRoutes);
app.get("/", (req, res) => {
  res.json({
    message: "Support Ticket API is running 🚀",
  });
});

app.use("/api/auth", authRoutes);

app.use("/api/tickets", ticketRoutes);

app.use(errorMiddleware);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(
    `Server running at http://localhost:${PORT}`
  );
});