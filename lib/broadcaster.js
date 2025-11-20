// lib/broadcaster.js
let ioInstance = null;

function setIo(io) {
  ioInstance = io;
}

function emitTerminalStatusChange(payload) {
  if (!ioInstance) {
    console.warn('[broadcaster] io not set yet, dropping event', payload && payload.terminalId);
    return;
  }
  // Keep payload small
  const p = {
    terminalId: payload.terminalId,
    isOnline: !!payload.isOnline,
    lastSeen: payload.lastSeen || null,
    status: payload.status || {}
  };
  ioInstance.emit('terminal:status', p);
}

module.exports = { setIo, emitTerminalStatusChange };
