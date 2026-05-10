const express = require('express');
const mongoose = require('mongoose');
const socketio = require('socket.io');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: { origin: "*" }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'));

// User Schema
const UserSchema = new mongoose.Schema({
  uniqueId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

// Message Schema
const MessageSchema = new mongoose.Schema({
  fromId: String,
  toId: String,
  message: String,
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

// Generate 5-digit unique ID
async function generateUniqueId() {
  let id, exists;
  do {
    id = Math.floor(10000 + Math.random() * 90000).toString();
    exists = await User.findOne({ uniqueId: id });
  } while (exists);
  return id;
}

// Register API
app.post('/api/register', async (req, res) => {
  const { name, password } = req.body;
  const uniqueId = await generateUniqueId();
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ uniqueId, name, password: hashedPassword });
  await user.save();
  res.json({ success: true, uniqueId });
});

// Login API
app.post('/api/login', async (req, res) => {
  const { uniqueId, password } = req.body;
  const user = await User.findOne({ uniqueId });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ uniqueId, name: user.name }, process.env.JWT_SECRET);
  res.json({ success: true, token, uniqueId, name: user.name });
});

// Get user info (protected)
app.get('/api/user', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ uniqueId: decoded.uniqueId, name: decoded.name });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Get messages between two users
app.post('/api/messages', async (req, res) => {
  const { fromId, toId } = req.body;
  const messages = await Message.find({
    $or: [
      { fromId, toId },
      { fromId: toId, toId: fromId }
    ]
  }).sort('timestamp');
  res.json(messages);
});

// Socket.io
const users = {}; // socketId -> user data
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  users[socket.id] = socket.user;
  console.log(`${socket.user.name} connected`);

  socket.on('send-message', async (data) => {
    const { toId, message } = data;
    const fromId = socket.user.uniqueId;
    
    // Save to database
    const newMsg = new Message({ fromId, toId, message });
    await newMsg.save();

    // Send to recipient if online
    const recipientSocket = Object.keys(users).find(
      key => users[key].uniqueId === toId
    );
    if (recipientSocket) {
      io.to(recipientSocket).emit('receive-message', {
        fromId,
        message,
        timestamp: newMsg.timestamp
      });
    }
  });

  socket.on('disconnect', () => {
    delete users[socket.id];
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));