import Ticket from "../models/Ticket.js";
import triageTicket from "../utils/triage.js";
import assignAgent from "../utils/assignAgent.js";

export const createTicket = async (req, res) => {
  try {
    const { subject, description } = req.body;

    if (!subject || !description) {
      return res.status(400).json({
        message: "Subject and description are required",
      });
    }

    const classification = triageTicket(
      subject,
      description
    );

    const agent = await assignAgent(
      classification.department
    );

    const ticket = await Ticket.create({
      subject,
      description,

      attachment: req.file
        ? `/uploads/${req.file.filename}`
        : null,

      urgency: classification.urgency,
      department: classification.department,
      tags: classification.tags,

      client: req.user._id,

      assignedAgent: agent
        ? agent._id
        : null,
    });

    const populatedTicket =
      await Ticket.findById(ticket._id)
        .populate("client", "name email")
        .populate(
          "assignedAgent",
          "name email department"
        );

    res.status(201).json({
      message:
        "Ticket submitted successfully. Our support team has been notified.",
      ticket: populatedTicket,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export const getMyTickets = async (req, res) => {
  try {
    const tickets = await Ticket.find({
      client: req.user._id,
    })
      .populate(
        "assignedAgent",
        "name email department"
      )
      .sort({ createdAt: -1 });

    res.json(tickets);
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export const getAgentTickets = async (req, res) => {
  try {
    const {
      urgency,
      department,
      status,
    } = req.query;

    const filter = {
      assignedAgent: req.user._id,
    };

    if (urgency) {
      filter.urgency = urgency;
    }

    if (department) {
      filter.department = department;
    }

    if (status) {
      filter.status = status;
    }

    const tickets = await Ticket.find(filter)
      .populate("client", "name email")
      .sort({ createdAt: -1 });

    res.json(tickets);
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export const getTicket = async (req, res) => {
  try {
    const ticket = await Ticket.findById(
      req.params.id
    )
      .populate("client", "name email")
      .populate(
        "assignedAgent",
        "name email department"
      );

    if (!ticket) {
      return res.status(404).json({
        message: "Ticket not found",
      });
    }

    const clientOwnsTicket =
      ticket.client._id.toString() ===
      req.user._id.toString();

    const agentOwnsTicket =
      ticket.assignedAgent &&
      ticket.assignedAgent._id.toString() ===
        req.user._id.toString();

    if (!clientOwnsTicket && !agentOwnsTicket) {
      return res.status(403).json({
        message: "Not authorized",
      });
    }

    res.json(ticket);
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export const updateTicketStatus = async (
  req,
  res
) => {
  try {
    const { status } = req.body;

    const allowedStatuses = [
      "Open",
      "In Progress",
      "Resolved",
      "Closed",
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        message: "Invalid ticket status",
      });
    }

    const ticket = await Ticket.findById(
      req.params.id
    );

    if (!ticket) {
      return res.status(404).json({
        message: "Ticket not found",
      });
    }

    if (
      !ticket.assignedAgent ||
      ticket.assignedAgent.toString() !==
        req.user._id.toString()
    ) {
      return res.status(403).json({
        message:
          "This ticket is not assigned to you",
      });
    }

    ticket.status = status;

    await ticket.save();

    res.json({
      message: "Ticket status updated",
      ticket,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export const getAgentStats = async (
  req,
  res
) => {
  try {
    const filter = {
      assignedAgent: req.user._id,
    };

    const total = await Ticket.countDocuments(
      filter
    );

    const open = await Ticket.countDocuments({
      ...filter,
      status: "Open",
    });

    const inProgress =
      await Ticket.countDocuments({
        ...filter,
        status: "In Progress",
      });

    const resolved =
      await Ticket.countDocuments({
        ...filter,
        status: "Resolved",
      });

    const critical =
      await Ticket.countDocuments({
        ...filter,
        urgency: "Critical",
      });

    res.json({
      total,
      open,
      inProgress,
      resolved,
      critical,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};