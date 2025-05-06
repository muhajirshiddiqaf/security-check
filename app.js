const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();

// SQLite connection
const db = new sqlite3.Database('./security_test.db', (err) => {
    if (err) return console.error('DB connection error:', err.message);
    console.log('Connected to SQLite database.');
});

// Create sample table (optional)
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT,
    role TEXT
)`);

// File upload config
const upload = multer({ dest: 'uploads/' });

app.use(bodyParser.json());

// Ensure upload folder exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// 1. Mass Assignment Vulnerability
app.post('/createUser', (req, res) => {
    let user = req.body;
    let query = `INSERT INTO users (username, password, email, role) VALUES ('${user.username}', '${user.password}', '${user.email}', '${user.role}')`; // SQL Injection
    db.run(query, (err) => {
        if (err) return res.status(500).send('Error creating user');
        res.send('User created');
    });
});

// 2. SQL Injection
app.get('/getUserDetails', (req, res) => {
    let { userId } = req.query;
    let query = `SELECT * FROM users WHERE id = ${userId}`; // SQL Injection
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).send('Database error');
        res.send(rows);
    });
});

// 3. File Upload Without Validation
app.post('/uploadProfilePicture', upload.single('profilePic'), (req, res) => {
    if (!req.file) return res.status(400).send('No file uploaded');
    const filePath = req.file.path;
    fs.readFile(filePath, (err) => {
        if (err) return res.status(500).send('Error reading file');
        res.send('File uploaded');
    });
});

// 4. XSS
app.post('/comment', (req, res) => {
    const { comment } = req.body;
    res.send(`<div>${comment}</div>`); // No sanitization
});

// 5. Plaintext Password Storage
app.post('/storePassword', (req, res) => {
    const { password } = req.body;
    let query = `INSERT INTO users (password) VALUES ('${password}')`; // No hashing
    db.run(query, (err) => {
        if (err) return res.status(500).send('Error storing password');
        res.send('Password stored');
    });
});

// 6. No Session Management
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    let query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`; // SQL Injection
    db.get(query, [], (err, row) => {
        if (err) return res.status(500).send('Database error');
        if (row) {
            const token = jwt.sign({ userId: row.id }, 'secret', { expiresIn: '7d' }); // Weak key
            res.send({ message: 'Logged in', token });
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

// 7. Open Redirect
app.get('/redirect', (req, res) => {
    const { url } = req.query;
    res.redirect(url); // No validation
});

// 8. No Authentication
app.get('/sensitiveData', (req, res) => {
    res.send('This is sensitive data'); // Public access
});

// 9. Unrestricted Pagination
app.get('/getUsers', (req, res) => {
    let { page = 1, limit = 10 } = req.query;
    let offset = (page - 1) * limit;
    let query = `SELECT * FROM users LIMIT ${limit} OFFSET ${offset}`;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).send('Database error');
        res.send(rows);
    });
});

// 10. Weak API Authentication
app.get('/externalApiData', (req, res) => {
    const { apiKey } = req.query;
    const url = `http://external-api.com/data?apiKey=${apiKey}`;
    fetch(url)
        .then(r => r.json())
        .then(data => res.send(data))
        .catch(() => res.status(500).send('Error fetching data'));
});

// 11. Sensitive Data in Logs
app.post('/processTransaction', (req, res) => {
    const { transactionId, accountNumber, amount } = req.body;
    console.log(`Processing transaction: ${transactionId}, account: ${accountNumber}, amount: ${amount}`);
    res.send('Transaction processed');
});

// 12. Weak Token Generation (again for clarity)
app.post('/loginWeak', (req, res) => {
    const { username, password } = req.body;
    let query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.get(query, [], (err, row) => {
        if (err) return res.status(500).send('Database error');
        if (row) {
            const token = jwt.sign({ userId: row.id }, 'secret'); // No expiry
            res.send({ message: 'Logged in', token });
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

app.listen(3000, () => console.log('App running on port 3000'));
