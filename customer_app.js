// Importing necessary libraries and modules
const mongoose = require('mongoose');
const Customers = require('./customer');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');  // Added JWT library
const { ValidationError, InvalidUserError, AuthenticationFailed } = require('./errors/CustomError');
const { stringify } = require('querystring');
const winston = require('winston');

const saltRounds = 5;
const secretKey = 'your-secret-key';  // Replace with a secure secret key
 
// A dictionary object to store username and password
let usersdic = {};
 
// Creating an instance of the Express application
const app = express();
 
// Setting the port number for the server
const port = 3000;
 
// MongoDB connection URI and database name
const uri = "mongodb://localhost:27017";
mongoose.connect(uri, { dbName: 'customerDB' });
 
// Middleware to parse JSON requests
app.use('*', bodyParser.json());
 
// Serving static files from the 'frontend' directory under the '/static' route
app.use('/static', express.static(path.join('.', 'frontend')));
 
// Middleware to handle URL-encoded form data
app.use(bodyParser.urlencoded({ extended: true }));
 
// Winston logger
const fileTransport = new winston.transports.File({ filename: 'logfile.log' });
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
          return `${timestamp} [${level}]: ${message}`;
        })
      )
    }),
    fileTransport
  ]
});

// POST /api/login
app.post('/api/login', async (req, res, next) => {
  const { user_name, password } = req.body;

  try {
    const user = await Customers.findOne({ user_name });
    if (!user) {
      fileTransport.log({
        level: 'warn',
        message: `Login failed for non-existing user: ${user_name}`,
        timestamp: new Date().toISOString()
      });
      throw new InvalidUserError("No such user in database");
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      fileTransport.log({
        level: 'warn',
        message: `Invalid password attempt for user: ${user_name}`,
        timestamp: new Date().toISOString()
      });
      throw new AuthenticationFailed("Passwords don't match");
    }

    const token = jwt.sign({ id: user._id, user_name: user.user_name }, secretKey, { expiresIn: '1h' });
    res.json({ message: "User Logged In", token });
  } catch (error) {
    next(error);
  }
});

// POST /api/add_customer
app.post('/api/add_customer', async (req, res, next) => {
  const { user_name, age, password, email } = req.body;

  try {
    // Validations
    if (isNaN(parseInt(age, 10)) || parseInt(age, 10) < 21) {
      throw new ValidationError("Customer under required age limit");
    }
    if (typeof user_name !== 'string' || user_name.trim() === '') {
      throw new ValidationError("Name must be a non-empty string");
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      throw new ValidationError("Password must be at least 6 characters");
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new ValidationError("Invalid email format");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create and save
    const customer = new Customers({ user_name, age, password: hashedPassword, email });
    await customer.save();

    logger.info(`Customer added: ${user_name}`);
    res.status(201).send("Customer added successfully");
  } catch (error) {
    if (error instanceof ValidationError) {
      fileTransport.log({
        level: 'warn',
        message: `Validation error for username: ${user_name} - ${error.message}`,
        timestamp: new Date().toISOString()
      });
    }
    next(error);
  }
});



 
// GET endpoint for the root URL, serving the home page
app.get('/', async (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'home.html'));
});

app.use((err,req,res,next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || "Error";
    console.log(err.stack);
    res.status(err.statusCode).json({
        status: err.statusCode,
        message: err.message,
    });
})
 
app.all("*",(req,res,next)=>{
    const err = new Error(`Cannot find the URL ${req.originalUrl} in this application. Please check.`);
    err.status = "Endpoint Failure";
    err.statusCode = 404;
    next(err);
})
// Function to authenticate JWT token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
 
    if (!token) {
        res.sendStatus(401);
        return;
    }
 
    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            res.sendStatus(403);
            return;
        }
 
        req.user = user;
        next();
    });
}
 
// GET endpoint for user logout
app.get('/api/logout', async (req, res) => {
    res.cookie('username', '', { expires: new Date(0) });
    res.redirect('/');
});

// Starting the server and listening on the specified port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});