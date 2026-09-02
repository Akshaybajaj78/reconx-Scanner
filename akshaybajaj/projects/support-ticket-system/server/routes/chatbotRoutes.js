import express from "express";
import { chatbot } from "../controllers/chatbotController.js";
import { protect } from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/", protect, chatbot);

export default router;