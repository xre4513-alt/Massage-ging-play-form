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
  cors: { origin: "*" },
  transports: ['websocket', 'polling']
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  uniqueId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
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

// ============ API ROUTES ============

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) {
      return res.status(400).json({ error: 'Name and password required' });
    }
    const uniqueId = await generateUniqueId();
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ uniqueId, name, password: hashedPassword });
    await user.save();
    res.json({ success: true, uniqueId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { uniqueId, password } = req.body;
    const user = await User.findOne({ uniqueId });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Wrong password' });
    }
    const token = jwt.sign({ uniqueId, name: user.name }, process.env.JWT_SECRET);
    res.json({ success: true, token, uniqueId, name: user.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all users (except current)
app.get('/api/all-users', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const users = await User.find({ uniqueId: { $ne: decoded.uniqueId } }, 'uniqueId name');
    res.json(users);
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Get messages between two users
app.post('/api/messages', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    jwt.verify(token, process.env.JWT_SECRET);
    
    const { fromId, toId } = req.body;
    const messages = await Message.find({
      $or: [
        { fromId, toId },
        { fromId: toId, toId: fromId }
      ]
    }).sort('timestamp');
    res.json(messages);
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Save message
app.post('/api/save-message', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const { toId, message } = req.body;
    const newMsg = new Message({ fromId: decoded.uniqueId, toId, message });
    await newMsg.save();
    res.json({ success: true });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ============ SOCKET.IO ============
const onlineUsers = new Map(); // uniqueId -> socket.id

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
  console.log(`✅ User connected: ${socket.user.name} (${socket.user.uniqueId})`);
  onlineUsers.set(socket.user.uniqueId, socket.id);

  socket.on('send-message', async (data) => {
    const { toId, message } = data;
    const fromId = socket.user.uniqueId;
    
    // Save to database
    const newMsg = new Message({ fromId, toId, message });
    await newMsg.save();

    // Send to recipient if online
    const recipientSocketId = onlineUsers.get(toId);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('receive-message', {
        fromId,
        message,
        timestamp: newMsg.timestamp
      });
    }
  });

  socket.on('disconnect', () => {
    console.log(`❌ User disconnected: ${socket.user?.uniqueId}`);
    onlineUsers.delete(socket.user?.uniqueId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
