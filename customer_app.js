// Importing necessary libraries and modules
const mongoose = require('mongoose');
const Customers = require('./customer');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');  // Added JWT library
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
 
// POST endpoint for user login with JWT authentication
app.post('/api/login', async (req, res) => {
    const data = req.body;
    console.log(data);
 
    const user_name = data['user_name'];
    const password = data['password'];
 
    const user = usersdic[user_name];
    if (!user || !(await bcrypt.compare(password, user.hashedpwd))) {
        res.status(401).send('User Information incorrect');
        return;
    }
 
    // No need to print details to the terminal, just send a success message
    res.status(200).send('Login successfully');
});
 
// POST endpoint for adding a new customer with JWT authentication
app.post('/api/add_customer', async (req, res) => {
    const data = req.body;
    console.log(data);
 
    const documents = await Customers.find({ user_name: data['user_name'] });
    if (documents.length > 0) {
        res.status(409).send('User already exists');
        return;
    }
 
    const hashedpwd = await bcrypt.hash(data['password'], saltRounds);
    usersdic[data['user_name']] = { hashedpwd };
 
    // Creating a new instance of the Customers model with data from the request
    const customer = new Customers({
        user_name: data['user_name'],
        age: data['age'],
        password: hashedpwd,
        email: data['email'],
    });
 
    // Saving the new customer to the MongoDB 'customers' collection
    await customer.save();
 
    res.status(201).send('Customer added successfully');
});
 
// GET endpoint for the root URL, serving the home page
app.get('/', async (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'home.html'));
});
 
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
 
// Starting the server and listening on the specified port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});