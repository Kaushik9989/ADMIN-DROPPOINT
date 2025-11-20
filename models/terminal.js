// models/Terminal.js
const mongoose = require('mongoose');

const HealthSchema = new mongoose.Schema({
  battery: {
    percent: { type: Number },
    charging: { type: Boolean },
    temp: { type: Number },
    cycleCount: { type: Number }
  },
  cpu: {
    loadPercent: { type: Number },
    avgLoad: { type: Number },
    cores: { type: Number },
    temp: { type: Number }
  },
  memory: {
    totalBytes: { type: Number },
    freeBytes: { type: Number },
    usedBytes: { type: Number }
  },
  disk: [{
    fs: String,
    mount: String,
    size: Number,
    used: Number,
    usePercent: Number
  }],
  wifi: {
    ssid: String,
    bssid: String,
    signalLevel: Number,    // dBm style if available
    linkSpeed: Number
  },
  networkInterfaces: [{
    iface: String,
    ip4: String,
    ip6: String,
    mac: String
  }],
  uptimeSeconds: Number,
  processesCount: Number,
  screenOn: Boolean,
  extra: mongoose.Schema.Types.Mixed
}, { _id: false });

const HistoryEntry = new mongoose.Schema({
  ts: { type: Date, default: Date.now },
  health: HealthSchema
}, { _id: false });

const TerminalSchema = new mongoose.Schema({
  terminalId: { type: String, unique: true, required: true },
  lastSeen: { type: Date, default: null },
  status: {
    localTime: Date,
    online: { type: Boolean, default: false },
    updatedBy: String,
    offlineAt: Date,
    health: HealthSchema
  },
  history: { type: [HistoryEntry], default: [] }
}, { timestamps: true });

// Indexes to help searches and watchdog queries
TerminalSchema.index({ lastSeen: 1 });
TerminalSchema.index({ 'status.online': 1 });
TerminalSchema.index({ terminalId: 1 });

// Convenience instance method to compute online (not stored)
TerminalSchema.methods.isOnline = function(thresholdMs = 30000) {
  if (!this.lastSeen) return false;
  return (Date.now() - this.lastSeen.getTime()) <= thresholdMs;
};

module.exports = mongoose.model('Terminal', TerminalSchema);
