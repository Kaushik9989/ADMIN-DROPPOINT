// models/FunnelEvent.js
const mongoose = require("mongoose");

const funnelEventSchema = new mongoose.Schema({
  sessionId: String, // From req.sessionID or generated
  userId: String, // optional, if user is logged in
  phone: String, // optional
  step: String, // e.g. "visit_landing_page"
  timestamp: { type: Date, default: Date.now },
  metadata: mongoose.Schema.Types.Mixed,
});

module.exports = mongoose.model("FunnelEvent", funnelEventSchema);
