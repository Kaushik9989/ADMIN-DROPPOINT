const mongoose = require("mongoose");

const PartnerSchema = new mongoose.Schema({
  name: String,              // "Amazon"
  apiKey: { type: String, unique: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Partner", PartnerSchema);
