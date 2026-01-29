const mongoose = require("mongoose");

const customerAgentSchema = new mongoose.Schema(
  {
    // Identity
    agentId: {
      type: String, // AGT-0001
      unique: true,
      index: true,
    },

    name: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      unique: true,
      index: true,
    },

    phone: {
      type: String,
      index: true,
    },

    // Auth
    passwordHash: {
      type: String, // bcrypt hash
    },

    role: {
      type: String,
      enum: ["agent", "supervisor", "admin"],
      default: "agent",
      index: true,
    },

    // Status
    status: {
      type: String,
      enum: ["offline", "online", "busy", "on_break"],
      default: "offline",
      index: true,
    },

    // Workload
    activeTickets: {
      type: Number,
      default: 0,
    },

    maxConcurrentTickets: {
      type: Number,
      default: 5,
    },

    // Performance stats
    stats: {
      ticketsResolved: { type: Number, default: 0 },
      ticketsClaimed: { type: Number, default: 0 },
      avgResolutionTimeSeconds: { type: Number, default: 0 },
      slaBreaches: { type: Number, default: 0 },
    },

    // Permissions
    permissions: {
      canUnlock: { type: Boolean, default: true },
      canEscalate: { type: Boolean, default: true },
      canCloseTickets: { type: Boolean, default: true },
      canViewVideo: { type: Boolean, default: true },
    },

    // Meta
    lastLoginAt: Date,
    lastSeenAt: Date,

    // Soft delete
    isActive: {
      type: Boolean,
      default: true,
      index: true,
    },
    googleId: { type: String, index: true },


  },
  { timestamps: true }
);

module.exports = mongoose.model("CustomerAgent", customerAgentSchema);
