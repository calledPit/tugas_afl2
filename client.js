const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:4000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> "
});

let registeredUsername = "";
let username = "";
const users = new Map();
let targetUsername = "";

// Generate RSA key pair for the client
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" }
});

// Hashing function for message integrity
function hashMessage(message) {
  return crypto.createHash("sha256").update(message).digest("hex");
}

socket.on("connect", () => {
  console.log("Connected to the server");
  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    // Register Public Key with the server
    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();
  });
});

rl.on("line", (message) => {
  if (message.trim()) {
    if ((match = message.match(/^!impersonate (\w+)$/))) {
      username = match[1];
      console.log(`Now impersonating as ${username}`);
    } else if ((match = message.match(/^!secret (\w+)$/))) {
      targetUsername = match[1];
      console.log(`Now secretly chatting with ${targetUsername}`);
    } else if (message.match(/^!exit$/)) {
      username = registeredUsername;
      targetUsername = "";
      console.log(`Now you are ${username} (broadcast mode)`);
    } else {
      let messageToSend = message;

      //logic to encrypt the message if targetUsername is set
      if (targetUsername) {
        const targetPublicKey = users.get(targetUsername);
        if (targetPublicKey) {
          const encryptedBuffer = crypto.publicEncrypt(targetPublicKey, Buffer.from(messageToSend));
          messageToSend = encryptedBuffer.toString("base64");
        } else {
          console.log(`User ${targetUsername} not found!`);
          rl.prompt();
          return;
        }
      }

      // Assignment #1: Hash the message
      const hash = hashMessage(messageToSend);

      // Assignment #2: Create Digital Signature
      const sign = crypto.createSign("SHA256");
      sign.update(messageToSend);
      sign.end();
      const signature = sign.sign(privateKey, "hex");

      // Send to server
      socket.emit("message", { username, message: messageToSend, hash, signature });
    }
  }
  rl.prompt();
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage, hash, signature } = data;
  if (senderUsername !== username) {

    // 1. Verify Hash (Integrity)
    const calculatedHash = hashMessage(senderMessage);
    if (calculatedHash !== hash) {
      console.log("\n[WARNING]: The message may have been changed during transmission!");
    }

    // 2. Verify Digital Signature (Authentication)
    const senderPublicKey = users.get(senderUsername);
    if (senderPublicKey) {
      const verify = crypto.createVerify("SHA256");
      verify.update(senderMessage);
      verify.end();
      const isValid = verify.verify(senderPublicKey, signature, "hex");
      if (!isValid) {
        console.log(`\n[WARNING]: This user (${senderUsername}) is FAKE!`);
      }
    } else {
      console.log(`\n[WARNING]: Public key for ${senderUsername} not found!`);
    }

    // 3. Attempt to Decrypt (Confidentiality)
    let displayMessage = senderMessage;
    try {
      // If it successfully decrypts, it means the secret message was for us
      const decryptedBuffer = crypto.privateDecrypt(privateKey, Buffer.from(senderMessage, "base64"));
      displayMessage = `(Secret) ${decryptedBuffer.toString("utf8")}`;
    } catch (err) {
      // If it fails to decrypt, it is either a broadcast plaintext, or a secret ciphertext meant for someone else.
      // We just display it as is.
    }

    console.log(`${senderUsername}: ${displayMessage}`);
    rl.prompt();
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
