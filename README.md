# Customer Portal Auth API

An Express.js API for user registration and login in a customer portal. This project uses MongoDB for data storage and implements secure password hashing for user authentication.

## Features

- User registration with hashed passwords
- User login with password verification
- MongoDB integration using Mongoose
- Basic input validation (can be extended)
- Ready for integration with frontend customer portals

## Technologies Used

- Node.js
- Express.js
- MongoDB & Mongoose
- bcrypt for password hashing
- (Optional) JSON Web Tokens (JWT) for authentication

## Getting Started

### Prerequisites

- Node.js installed
- MongoDB instance (local or cloud)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/customer-portal-auth-api.git# coding-project-template

2.Install dependencies:

cd customer-portal-auth-api
npm install

3.Create a .env file in the root directory and add your MongoDB URI and other environment variables:
MONGO_URI=your_mongodb_connection_string
PORT=5000
JWT_SECRET=your_jwt_secret (if using JWT)

4.Start the server:
npm start

