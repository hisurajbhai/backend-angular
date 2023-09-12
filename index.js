const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise'); // Import mysql2 promise-based version
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());

// Create a MySQL connection pool
const db = mysql.createPool({
    host: process.env.MYSQL_HOST,
    port: process.env.MYSQL_PORT,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    waitForConnections: true,
    connectionLimit: 10, // Adjust this value as needed
    queueLimit: 0,
});

// Registration Route
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const connection = await db.getConnection();

        // Check if the username already exists in the database
        const checkUsernameQuery = 'SELECT * FROM users WHERE username = ?';
        const [existingUser] = await connection.query(checkUsernameQuery, [username]);

        if (existingUser.length > 0) {
            connection.release();
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the user into the database
        const createUserQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
        await connection.query(createUserQuery, [username, hashedPassword]);

        connection.release();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Registration failed' });
    }
});

// Login Route
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const connection = await db.getConnection();

        // Check if the username exists in the database
        const getUserQuery = 'SELECT * FROM users WHERE username = ?';
        const [users] = await connection.query(getUserQuery, [username]);

        if (users.length === 0) {
            connection.release();
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = users[0];

        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.password);

        connection.release();

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate a JWT token
        const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, {
            expiresIn: '1h', // Token expires in 1 hour
        });

        res.status(200).json({ token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Login failed' });
    }
});

// Protected Route for Fetching User Profile
app.get('/api/profile', authenticateToken, (req, res) => {
    // The user object is attached to the request object by the authenticateToken middleware
    const { userId, username } = req.user;

    // You can fetch the user's profile information from the database here
    // Example: const userProfile = fetchUserProfileFromDatabase(userId);

    res.status(200).json({ userId, username });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const token = req.header('Authorization');
    if (token == null) return res.status(401).json({ message: 'Authentication required' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

app.get('/api/welcome', (req, res) => {
    res.send('Welcome to my page!');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
