const express = require('express');
const bodyParser = require('body-parser');
const { Client } = require('pg');
const multer = require('multer');
const fs = require('fs');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();


// PostgreSQL client connection
const client = new Client({
    user: 'postgres',  // Replace with your PostgreSQL username
    host: 'localhost',
    database: 'security_test',
    password: '17101997',  // Replace with your PostgreSQL password
    port: 5432,
});


// Connect to the database
client.connect();

// Middleware for file uploads (bad: no validation)
const upload = multer({ dest: 'uploads/' });

app.use(bodyParser.json());

// Ensure the upload directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// 1. **Mass Assignment Vulnerability**
app.post('/createUser', (req, res) => {
    let user = req.body; // No validation, no sanitization
    let query = `INSERT INTO users (username, password, email, role) VALUES ('${user.username}', '${user.password}', '${user.email}', '${user.role}')`;  // **Bad: Dangerous SQL Injection**
    client.query(query)
        .then(() => res.send('User created'))
        .catch(err => res.status(500).send('Error creating user'));
});

// 2. **SQL Injection**
app.get('/getUserDetails', (req, res) => {
    let { userId } = req.query;
    let query = `SELECT * FROM users WHERE id = ${userId}`;  // **Bad: SQL Injection vulnerability**
    client.query(query)
        .then(result => res.send(result.rows))
        .catch(err => res.status(500).send('Database error'));
});

// 3. **File Upload Without Validation**
app.post('/uploadProfilePicture', upload.single('profilePic'), (req, res) => {
    // Check if the file was uploaded
    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }

    const filePath = req.file.path;  // File path after upload
    // **Bad: Allows uploading potentially dangerous files (e.g., .php or .exe)**
    fs.readFile(filePath, (err, data) => {
        if (err) {
            return res.status(500).send('Error reading file');
        }
        res.send('File uploaded');
    });
});

// 4. **Cross-Site Scripting (XSS) Vulnerability**
app.post('/comment', (req, res) => {
    const { username, comment } = req.body;
    // **Bad: Directly rendering user input without sanitization (XSS vulnerability)**
    res.send(`<div>${comment}</div>`); // Attacker could inject malicious scripts here
});

// 5. **Password Stored in Plaintext**
app.post('/storePassword', (req, res) => {
    const { password } = req.body;
    // **Bad: Storing passwords in plaintext**
    let query = `INSERT INTO users (password) VALUES ('${password}')`;  // **Bad: Plaintext password storage**
    client.query(query)
        .then(() => res.send('Password stored'))
        .catch(err => res.status(500).send('Error storing password'));
});

// 6. **Lack of Session Management (No Token Expiry)**
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    let query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;  // **Bad: SQL Injection**
    client.query(query)
        .then(result => {
            if (result.rows.length > 0) {
                // **Bad: No session management, no token expiry**
                const token = jwt.sign({ userId: result.rows[0].id }, 'secret', { expiresIn: '7d' });  // Weak token generation
                res.send({ message: 'Logged in successfully', token });
            } else {
                res.status(401).send('Invalid credentials');
            }
        })
        .catch(err => res.status(500).send('Database error'));
});

// 7. **Open Redirect**
app.get('/redirect', (req, res) => {
    let { url } = req.query;
    // **Bad: Open redirect vulnerability (No validation of URL)**
    res.redirect(url);  // Attacker can use this to redirect users to a malicious site
});

// 8. **No Authentication for Sensitive Data**
app.get('/sensitiveData', (req, res) => {
    // **Bad: No authentication or validation before serving sensitive data**
    res.send('This is sensitive data');  // Anyone can access this
});

// 9. **Unrestricted Pagination (No Max Limit Validation)**
app.get('/getUsers', (req, res) => {
    let { page, limit } = req.query;
    // **Bad: No limit validation, attackers can request too much data**
    let query = `SELECT * FROM users LIMIT ${limit} OFFSET ${(page - 1) * limit}`;  // **No maximum cap on `limit`**
    client.query(query)
        .then(result => res.send(result.rows))
        .catch(err => res.status(500).send('Database error'));
});

// 10. **Weak API Authentication**
app.get('/externalApiData', (req, res) => {
    const { apiKey } = req.query;
    // **Bad: Weak API authentication (apiKey is exposed in URL, no security checks)**
    const url = `http://external-api.com/data?apiKey=${apiKey}`;
    fetch(url)
        .then(response => response.json())
        .then(data => res.send(data))
        .catch(err => res.status(500).send('Error fetching data'));
});

// 11. **Sensitive Data in Logs**
app.post('/processTransaction', (req, res) => {
    const { transactionId, accountNumber, amount } = req.body;
    // **Bad: Transaction information is logged without encryption**
    console.log(`Processing transaction: ${transactionId} for account: ${accountNumber}, amount: ${amount}`);  // Sensitive data in logs
    res.send('Transaction processed');
});

// 12. **Weak Session Token Generation**
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    let query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;  // **Bad: SQL Injection**
    client.query(query)
        .then(result => {
            if (result.rows.length > 0) {
                // **Bad: Session token generated without sufficient entropy or expiration**
                const token = jwt.sign({ userId: result.rows[0].id }, 'secret', { expiresIn: '7d' });  // Weak secret
                res.send({ message: 'Logged in successfully', token });
            } else {
                res.status(401).send('Invalid credentials');
            }
        })
        .catch(err => res.status(500).send('Database error'));
});

app.listen(3000, () => console.log('App running on port 3000'));
