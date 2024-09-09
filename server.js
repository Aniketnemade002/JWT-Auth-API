const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors'); // Import the cors package

const server = express();
const router = jsonServer.router('./db.json'); // Database for other routes
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8')); // Load users from users.json

const SECRET_KEY = '123456789';
const JWT_EXPIRY = '1h';

server.use(cors()); // Enable CORS for all origins
server.use(bodyParser.json());

// Create a token from a payload 
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: JWT_EXPIRY });
}

// Verify the token 
function verifyToken(token) {
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch (error) {
    return error;
  }
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return userdb.users.some(user => user.email === email && user.password === password);
}

// Register New User
server.post('/auth/register', (req, res) => {
  console.log("Register endpoint called; request body:", req.body);
  const { email, password } = req.body;

  if (isAuthenticated({ email, password })) {
    return res.status(401).json({ status: 401, message: 'Email and Password already exist' });
  }

  fs.readFile('./users.json', (err, data) => {
    if (err) return res.status(500).json({ status: 500, message: 'Error reading users data' });

    let usersData = JSON.parse(data);
    const lastItemId = usersData.users.length > 0 ? usersData.users[usersData.users.length - 1].id : 0;

    usersData.users.push({ id: lastItemId + 1, email, password });

    fs.writeFile('./users.json', JSON.stringify(usersData), (err) => {
      if (err) return res.status(500).json({ status: 500, message: 'Error saving user data' });

      userdb.users = usersData.users;
      res.status(200).json({ status: 200, message: 'Registration Successful.' });
    });
  });
});

// Login
server.post('/auth/login', (req, res) => {
  console.log("Login endpoint called; request body:", req.body);
  const { email, password } = req.body;

  if (!isAuthenticated({ email, password })) {
    return res.status(401).json({ status: 401, message: 'Incorrect email or password OR User does not exist' });
  }

  const token = createToken({ email, password });
  const refreshToken = createToken({ email, password }); // Generate a new token

  res.status(200).json({ token, refreshToken });
});

// Refresh Token
server.post('/token', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, SECRET_KEY);
    const newToken = createToken(decoded);
    res.json({ token: newToken });
  } catch (error) {
    res.status(403).json({ message: 'Invalid refresh token' });
  }
});

// Middleware to check authorization for non-auth routes
server.use(/^(?!\/auth).*$/, (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log(authHeader);

  if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ status: 401, message: 'Error in authorization format' });
  }

  const token = authHeader.split(' ')[1];
  const verifyResult = verifyToken(token);

  // if (verifyResult instanceof Error) {
  //   return res.status(401).json({ status: 401, message: 'Access token not valid or expired' });
  // }

  next();
});

server.use(router);

server.listen(8000, () => {
  console.log('Run Auth API Server on port 8000');
});
