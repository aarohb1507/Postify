require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jsonwebtoken = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();
const User = require('./models/userModel');
const authRoutes = require('./routes/authRoutes');

// Middleware
app.use(express.json());
app.use(cookieParser());
//app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(bodyParser.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'secretKey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true }
}));

// Use routes
app.use('/api/auth', authRoutes);

// Configure CORS
const corsOptions = {
    origin: ['http://127.0.0.1:3001', 'http://localhost:3000'], // Allow both 127.0.0.1 and localhost with port 5500
    methods: ['GET', 'POST', 'OPTIONS'], // Allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allow headers
    credentials: true, // Allow cookies and authentication headers
  };
  
app.options('*', cors(corsOptions)); // Handle OPTIONS requests for CORS preflight

const cors = require('cors');
app.use(cors({
    origin: 'http://127.0.0.1:3001',
    credentials: true,
}));
 // Use the configured CORS settings

/* MongoDB connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/postify', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));
*/
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/postify')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));


// Signup Endpoint
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;

  // Basic Validation
  if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
  }
  // Simulate user creation logic (replace with real DB logic)
  console.log('User data received:', { username, email, password });

  return res.status(201).json({ message: 'User created successfully!' });

  try {
      // Check if the user already exists
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
          return res.status(400).json({ message: 'Username or Email already in use.' });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Save the user to the database
      const newUser = new User({
          username,
          email,
          password: hashedPassword,
      });

      await newUser.save();

      return res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Internal server error.' });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        // Create JWT token
        const token = jsonwebtoken.sign({ id: user._id }, process.env.jsonwebtoken_SECRET || 'secret', { expiresIn: '1d' });

        // Set session and cookie
        req.session.user = user;
        res.cookie('token', token, {
            httpOnly: true,  // This ensures JavaScript can't access the cookie
            secure: process.env.NODE_ENV === 'production', // Set to true if using HTTPS
            maxAge: 24 * 60 * 60 * 1000 // 1 day expiration
        });

        res.status(200).json({ message: 'Login successful', userId: user._id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Dashboard endpoint
app.get('/api/dashboard', (req, res) => {
    const token = req.cookies.token; // Get token from cookies

    if (!token) {
        return res.status(401).json({ message: 'Not authenticated' }); // No token found
    }

    try {
        // Verify the token
        const decoded = jsonwebtoken.verify(token, process.env.jsonwebtoken_SECRET || 'secret');
        req.user = decoded; // Store the decoded token (user data) in request
        res.status(200).json({ message: 'Authenticated', user: req.user });
    } catch (err) {
        console.error('Token verification failed:', err);
        res.status(401).json({ message: 'Invalid or expired token' });
    }
});

// Logout Endpoint
app.post('/api/auth/logout', (req, res) => {
    // Clear the session and token cookie
    res.clearCookie('token', { httpOnly: true, secure: false });
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.status(200).json({ message: 'Logout successful' });
    });
});

// Middleware for Authentication
const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: 'Not authenticated' });

    jsonwebtoken.verify(token, process.env.jsonwebtoken_SECRET || 'secret', (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Token invalid' });

        req.userId = decoded.id;
        next();
    });
};

// Example of a Protected Route
app.get('/api/dashboard', authenticate, (req, res) => {
    res.status(200).json({ message: 'Welcome to the dashboard!', userId: req.userId });
});

// Handle 404 for undefined routes
app.use((req, res) => {
    res.status(404).json({ message: 'Not found' });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});