// user-service/src/index.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based version
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // For Cross-Origin Resource Sharing

const app = express();
app.use(express.json()); // For parsing JSON request bodies
app.use(cors()); // Enable CORS for all routes (adjust origin for production)

// Database Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'user-db', // Docker Compose service name
  user: process.env.DB_USER || 'user_service_user',
  password: process.env.DB_PASSWORD || 'user_service_password',
  database: process.env.DB_NAME || 'user_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// JWT Secret (generate a strong one for production)
const JWT_SECRET = process.env.JWT_SECRET || 'aVeryStrongAndComplexSecretKeyForYourJWT'; // CHANGE THIS IN PRODUCTION

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes

// 1. Register User
app.post('/api/users/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ message: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userRole = role || 'customer'; // Default role to 'customer'

    await pool.query('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', [
      username,
      email,
      hashedPassword,
      userRole
    ]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 2. Login User
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 3. Get User Profile (Authenticated)
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, username, email, role, created_at FROM users WHERE id = ?', [req.user.id]);
    const user = users[0];
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 4. Update User Profile (Authenticated)
app.put('/api/users/profile', authenticateToken, async (req, res) => {
  const { username, email } = req.body;
  const userId = req.user.id;

  try {
    await pool.query('UPDATE users SET username = ?, email = ? WHERE id = ?', [username, email, userId]);
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 5. Delete User (Authenticated, Admin or self-delete)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  const userIdToDelete = req.params.id;

  if (req.user.id != userIdToDelete && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized to delete this user' });
  }

  try {
    await pool.query('DELETE FROM users WHERE id = ?', [userIdToDelete]);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`User Service running on port ${PORT}`);
});

// Initialize database schema (create table if not exists)
async function initializeDb() {
  try {
    const connection = await pool.getConnection();
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('customer', 'admin', 'technician') DEFAULT 'customer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('User table checked/created successfully.');
    connection.release();
  } catch (error) {
    console.error('Error initializing user database:', error);
    process.exit(1); // Exit if DB connection or table creation fails
  }
}

initializeDb();