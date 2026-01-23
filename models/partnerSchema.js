const mongoose = require("mongoose");

const PartnerSchema = new mongoose.Schema({
  // 👤 Person info (who logs in)
  name: { type: String, required: true },          // "Ramesh Kumar"
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },         // "9876543210"

  // 🏢 Company info
  companyName: { type: String, required: true },   // "Amazon"
  logoUrl: String,                                 // optional
  apiKey: { type: String, unique: true },
  // 🔐 Google OAuth
  googleId: { type: String, unique: true, sparse: true },

  // 🛡️ Access control
  isApproved: { type: Boolean, default: false },   // admin approval
  isActive: { type: Boolean, default: true },      // can login or not

  // 📊 Metadata
  lastLoginAt: Date,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Partner", PartnerSchema);
