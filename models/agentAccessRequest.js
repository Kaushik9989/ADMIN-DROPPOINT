const mongoose = require("mongoose");

const agentAccessRequestSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      required: true,
      index: true,
    },

    phone: String,

    reason: String,

    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
      index: true,
    },

    reviewedBy: String,
    reviewedAt: Date,
    adminNote: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("AgentAccessRequest", agentAccessRequestSchema);
