const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer();
const io = socketIo(server);

const users = new Map();

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);
  
  socket.emit("init", Array.from(users.entries()));

  socket.on("registerPublicKey", (data) => {
    const { username, publicKey } = data;
    users.set(username, publicKey);
    console.log(`${username} registered with public key.`);
    io.emit("newUser", { username, publicKey });
  });

  socket.on("message", (data) => {
    let { username, message, hash, signature } = data;
    // MALICIOUS SERVER MODIFICATION
    message = message + " (sus?)";
    io.emit("message", { username, message, hash, signature });
  });

  socket.on("disconnect", () => {
    console.log(`Client ${socket.id} disconnected`);
  });
});

const port = 4000;
server.listen(port, () => {
  console.log(`Malicious server running on port ${port}`);
});
