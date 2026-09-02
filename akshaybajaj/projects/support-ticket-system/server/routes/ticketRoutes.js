import express from "express";
import multer from "multer";

import {
  createTicket,
  getMyTickets,
  getAgentTickets,
  getTicket,
  updateTicketStatus,
  getAgentStats,
} from "../controllers/ticketController.js";

import {
  protect,
  authorizeRoles,
} from "../middleware/authMiddleware.js";

const router = express.Router();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },

  filename: (req, file, cb) => {
    cb(
      null,
      `${Date.now()}-${file.originalname}`
    );
  },
});

const upload = multer({ storage });

router.post(
  "/",
  protect,
  authorizeRoles("client"),
  upload.single("attachment"),
  createTicket
);

router.get(
  "/my",
  protect,
  authorizeRoles("client"),
  getMyTickets
);

router.get(
  "/assigned",
  protect,
  authorizeRoles("agent"),
  getAgentTickets
);

router.get(
  "/stats",
  protect,
  authorizeRoles("agent"),
  getAgentStats
);

router.get(
  "/:id",
  protect,
  getTicket
);

router.patch(
  "/:id/status",
  protect,
  authorizeRoles("agent"),
  updateTicketStatus
);

export default router;