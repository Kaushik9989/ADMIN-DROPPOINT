// socket.js
const { Server } = require("socket.io");

let io;

function initSocket(server) {
  io = new Server(server, {
    cors: { origin: "*" }
  });

  io.on("connection", (socket) => {
    console.log("Admin connected:", socket.id);
  });
}

function emitTerminalUpdate(payload) {
  if (io) {
    io.emit("terminal:update", payload);
  }
}

module.exports = {
  initSocket,
  emitTerminalUpdate
};
