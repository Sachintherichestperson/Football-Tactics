const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors({
  origin: 'http://localhost:3000', // Update with your frontend URL
  credentials: true
}));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// MongoDB connection
mongoose.connect('mongodb+srv://bajajsachin100:cl7wZHN6lgYl0ueV@football-tactics.ftpx93e.mongodb.net/', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const recordingSchema = new mongoose.Schema({
  name: String,
  frames: Array,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  recordings: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Recording' }]
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const Recording = mongoose.model('Recording', recordingSchema);
const User = mongoose.model('User', userSchema);

// Auth Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(401).json({ error: 'Not authenticated' });
  }
};
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/register.html");
});
// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const user = new User({ username, email, password });
    await user.save();

    // Create token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', {
      expiresIn: '1d'
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 86400000 // 1 day
    });

    res.redirect("/Football")
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

app.get("/Football", authenticate, (req, res) => {
  console.log("Authenticated user:", req.user);
  res.sendFile(__dirname + "/Football.html");
});

app.post('/api/login', authenticate, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', {
      expiresIn: '1d'
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 86400000 // 1 day
    });

    res.json({ 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/logout', authenticate, (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// Protected Routes
app.get('/api/me', authenticate, async (req, res) => {
  res.json({ 
    user: { 
      id: req.user._id, 
      username: req.user.username, 
      email: req.user.email 
    } 
  });
});

// Recording Routes
app.post('/api/recordings', authenticate, async (req, res) => {
  try {
    const { name, frames } = req.body;
    const recording = new Recording({ 
      name, 
      frames, 
      createdBy: req.user._id 
    });
    
    await recording.save();
    
    // Add recording to user's recordings
    await User.findByIdAndUpdate(req.user._id, {
      $push: { recordings: recording._id }
    });

    res.status(201).json(recording);
  } catch (error) {
    console.error('Save recording error:', error);
    res.status(500).json({ error: 'Failed to save recording' });
  }
});

app.get('/api/recordings', authenticate, async (req, res) => {
  try {
    const recordings = await Recording.find({ createdBy: req.user._id })
      .sort({ updatedAt: -1 });
    res.json(recordings);
  } catch (error) {
    console.error('Fetch recordings error:', error);
    res.status(500).json({ error: 'Failed to fetch recordings' });
  }
});

app.get('/api/recordings/:id', authenticate, async (req, res) => {
  try {
    const recording = await Recording.findOne({ 
      _id: req.params.id, 
      createdBy: req.user._id 
    });
    
    if (!recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }
    
    res.json(recording);
  } catch (error) {
    console.error('Fetch recording error:', error);
    res.status(500).json({ error: 'Failed to fetch recording' });
  }
});

app.put('/api/recordings/:id', authenticate, async (req, res) => {
  try {
    const recording = await Recording.findOneAndUpdate(
      { _id: req.params.id, createdBy: req.user._id },
      { 
        name: req.body.name,
        frames: req.body.frames, 
        updatedAt: Date.now() 
      },
      { new: true }
    );
    
    if (!recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }
    
    res.json(recording);
  } catch (error) {
    console.error('Update recording error:', error);
    res.status(500).json({ error: 'Failed to update recording' });
  }
});

app.delete('/api/recordings/:id', authenticate, async (req, res) => {
  try {
    const recording = await Recording.findOneAndDelete({
      _id: req.params.id,
      createdBy: req.user._id
    });
    
    if (!recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }
    
    // Remove recording from user's recordings
    await User.findByIdAndUpdate(req.user._id, {
      $pull: { recordings: recording._id }
    });
    
    res.json({ message: 'Recording deleted successfully' });
  } catch (error) {
    console.error('Delete recording error:', error);
    res.status(500).json({ error: 'Failed to delete recording' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
