// models/Merchant.js
const mongoose = require("mongoose");

const MerchantSchema = new mongoose.Schema({
  organization_name : {type : String},
  name: { type: String },
  phone: { 
    type: String, 
    required: true, 
    unique: true, 
    match: /^[6-9]\d{9}$/  // val+idates Indian 10-digit numbers
  },
  location_id: { type: mongoose.Schema.Types.ObjectId, ref: "DropLocation" },
  isActive: { type: Boolean, default: true },
  isValid : {type: Boolean, default : false},
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.models.Merchant || mongoose.model("Merchant", MerchantSchema);
