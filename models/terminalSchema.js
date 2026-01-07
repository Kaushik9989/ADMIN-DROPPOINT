const TerminalSchema = new mongoose.Schema({
  terminalId: String,
  status: {
    online: Boolean,
    lastSeen: Date,
    appRunning: Boolean,
    internet: Boolean
  },
  health: {
    cpu: Number,
    ramUsed: Number,
    diskUsed: Number
  },
  logs: [{
    ts: Date,
    message: String,
    level: String
  }]
});
