const mongoose = require("mongoose");

const userActionSchema = new mongoose.Schema({
  sessionId: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  step: String,                // e.g. 'login_phone', 'otp_entered', 'send_step_1'
  path: String,                // URL path
  method: String,              // 'click', 'pageview', etc.
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("UserAction", userActionSchema);
