const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const helmet = require('helmet');
const { db, initializeDatabase, dbQueries } = require('./db');

const app = express();
const PORT = 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    hsts: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false
}));

app.use(cors({
    origin: 'http://localhost:3000', // Restrict CORS
    credentials: true
}));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Sanitize filename
        const sanitizedFilename = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        cb(null, Date.now() + '-' + sanitizedFilename);
    }
});

// File filter for multer
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type'), false);
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Middleware
app.use(express.json({ limit: '1mb' })); // Limit JSON payload size
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../frontend')));

// Initialize database
initializeDatabase().then(() => {
    console.log('Database initialized with sample data');
}).catch(err => {
    console.error('Error initializing database:', err);
});

// CSRF token endpoint
app.get('/api/secure/csrf-token', (req, res) => {
    const token = Math.random().toString(36).substring(2);
    res.cookie('csrfToken', token, {
        httpOnly: true,
        secure: false, // Force HTTP
        sameSite: 'lax'
    });
    res.json({ token });
});

// Vulnerable ENDPOINTS

// 1. SQL Injection vulnerable endpoint
app.get('/api/vulnerable/search', (req, res) => {
    const query = req.query.q;
    // Vulnerable: Direct string concatenation with exact match
    db.all(`SELECT * FROM users WHERE username = '${query}'`, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// Add POST method for the same endpoint
app.post('/api/vulnerable/search', (req, res) => {
    const query = req.body.q;
    // Vulnerable: Direct string concatenation with exact match
    db.all(`SELECT * FROM users WHERE username = '${query}'`, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// 2. XSS vulnerable endpoint
app.post('/api/vulnerable/comments', (req, res) => {
    const { content, userId } = req.body;
    // Vulnerable: No input sanitization
    db.run(`INSERT INTO comments (content, user_id) VALUES (?, ?)`,
        [content, userId],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ id: this.lastID, content, userId });
        });
});

// 3. Command Injection vulnerable endpoint
app.post('/api/vulnerable/execute', (req, res) => {
    const { command } = req.body;
    // Vulnerable: Direct command execution
    exec(command, (error, stdout, stderr) => {
        if (error) {
            res.status(500).json({ error: error.message });
            return;
        }
        res.json({ output: stdout });
    });
});

// 4. Broken Authentication vulnerable endpoint
app.post('/api/vulnerable/login', (req, res) => {
    const { username, password } = req.body;
    // Vulnerable: Plain text password comparison
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        // Vulnerable: Direct password comparison without hashing
        if (user && password === 'admin123' && username === 'admin') {
            const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: '1h' });
            res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
        } else if (user && password === 'user123' && username === 'user') {
            const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: '1h' });
            res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
        } else if (user && password === 'guest123' && username === 'guest') {
            const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: '1h' });
            res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// 5. CSRF vulnerable endpoint
app.post('/api/vulnerable/admin/deleteAll', (req, res) => {
    // Vulnerable: No CSRF protection
    db.run('DELETE FROM comments', (err) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ message: 'All comments deleted' });
    });
});

// SECURE ENDPOINTS

// 1. SQL Injection secure endpoint
app.get('/api/secure/search', (req, res) => {
    const query = req.query.q;
    // Secure: Parameterized query with exact match
    db.all(`SELECT * FROM users WHERE username = ?`, [query], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// Add POST method for the secure endpoint
app.post('/api/secure/search', (req, res) => {
    const query = req.body.q;
    // Secure: Parameterized query with exact match
    db.all(`SELECT * FROM users WHERE username = ?`, [query], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// 2. XSS secure endpoint
app.post('/api/secure/comments', (req, res) => {
    const { content, userId } = req.body;
    // Secure: Input sanitization
    const sanitizedContent = content.replace(/[<>]/g, '');
    db.run(`INSERT INTO comments (content, user_id) VALUES (?, ?)`,
        [sanitizedContent, userId],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ id: this.lastID, content: sanitizedContent, userId });
        });
});

// 3. Command Injection secure endpoint
app.post('/api/secure/execute', (req, res) => {
    const { command } = req.body;
    // Secure: Command whitelist
    const allowedCommands = ['ls', 'pwd', 'date'];
    if (!allowedCommands.includes(command)) {
        res.status(400).json({ error: 'Invalid command' });
        return;
    }
    exec(command, (error, stdout, stderr) => {
        if (error) {
            res.status(500).json({ error: error.message });
            return;
        }
        res.json({ output: stdout });
    });
});

// 4. Secure Authentication endpoint
app.post('/api/secure/login', (req, res) => {
    const { username, password } = req.body;
    // Secure: Password hashing and JWT
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (user) {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const token = jwt.sign(
                    { id: user.id },
                    process.env.JWT_SECRET || 'secret',
                    { expiresIn: '1h' }
                );
                res.cookie('token', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict'
                });
                res.json({ token });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// 5. CSRF secure endpoint
app.post('/api/secure/admin/deleteAll', (req, res) => {
    const token = req.headers['x-csrf-token'];
    // Secure: CSRF token validation
    if (!token || token !== req.cookies.csrfToken) {
        res.status(403).json({ error: 'Invalid CSRF token' });
        return;
    }
    db.run('DELETE FROM comments', (err) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ message: 'All comments deleted' });
    });
});

// Vulnerable file upload endpoint
app.post('/api/vulnerable/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
    }
    res.json({ 
        message: 'File uploaded successfully', 
        path: req.file.path,
        filename: req.file.filename
    });
});

// Secure file upload endpoint
app.post('/api/secure/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
    }

    // Secure: File validation
    const allowedTypes = ['image/jpeg', 'image/png'];
    if (!allowedTypes.includes(req.file.mimetype)) {
        fs.unlinkSync(req.file.path); // Delete invalid file
        return res.status(400).json({ error: 'Invalid file type' });
    }

    res.json({ 
        message: 'File uploaded successfully', 
        path: req.file.path,
        filename: req.file.filename
    });
});

// Vulnerable user update endpoint (Mass Assignment)
app.post('/api/vulnerable/users/update', (req, res) => {
    const { id } = req.body;
    // Vulnerable: Mass assignment - accepting all fields without validation
    const updates = req.body;
    
    // Vulnerable: Directly using all fields from request body without any validation
    const updateFields = Object.keys(updates)
        .map(key => `${key} = ?`)
        .join(', ');
    const values = Object.values(updates);
    values.push(id);

    // Vulnerable: No validation at all, allowing any field to be updated
    db.run(`UPDATE users SET ${updateFields} WHERE id = ?`, values, (err) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ message: 'User updated successfully', updatedFields: updates });
    });
});

// Secure user update endpoint (Mass Assignment)
app.post('/api/secure/users/update', (req, res) => {
    const { id } = req.body;
    
    // Secure: Whitelist of allowed fields
    const allowedFields = ['email', 'name'];
    const updates = {};
    
    // Secure: Only allow specific fields to be updated
    for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
            // Secure: Additional validation for each field
            if (field === 'email' && !isValidEmail(req.body[field])) {
                return res.status(400).json({ error: 'Invalid email format' });
            }
            updates[field] = req.body[field];
        }
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: 'No valid fields to update' });
    }

    const updateFields = Object.keys(updates)
        .map(key => `${key} = ?`)
        .join(', ');
    const values = Object.values(updates);
    values.push(id);

    // Secure: Using parameterized query
    db.run(`UPDATE users SET ${updateFields} WHERE id = ?`, values, (err) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ 
            message: 'User updated successfully',
            updatedFields: Object.keys(updates)
        });
    });
});

// Helper function for email validation
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Vulnerable redirect endpoint (Open Redirect)
app.get('/api/vulnerable/redirect', (req, res) => {
    const { url } = req.query;
    // Vulnerable: No validation of redirect URL
    res.redirect(url);
});

// Secure redirect endpoint (Open Redirect)
app.get('/api/secure/redirect', (req, res) => {
    const { url } = req.query;
    // Secure: URL validation
    if (!isAllowedDomain(url)) {
        return res.status(400).json({ error: 'Invalid redirect URL' });
    }
    res.redirect(url);
});

// Vulnerable API Authentication endpoint
app.get('/api/vulnerable/data', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    // Vulnerable: Weak API key validation
    if (apiKey === '123456') {
        res.json({ data: 'Sensitive data' });
    } else {
        res.status(401).json({ error: 'Invalid API key' });
    }
});

// Secure API Authentication endpoint
app.get('/api/secure/data', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        // Secure: JWT verification
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        res.json({ data: 'Sensitive data' });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Vulnerable Sensitive Data Logging endpoint
app.post('/api/vulnerable/log', (req, res) => {
    const { data } = req.body;
    // Vulnerable: Logs sensitive data
    console.log('User data:', data);
    res.json({ message: 'Data logged' });
});

// Secure Sensitive Data Logging endpoint
app.post('/api/secure/log', (req, res) => {
    const { data } = req.body;
    // Secure: Sanitize sensitive data before logging
    const sanitizedData = sanitizeLogData(data);
    console.log('User action:', sanitizedData);
    res.json({ message: 'Data logged' });
});

// Helper functions
function isAllowedDomain(url) {
    const allowedDomains = ['example.com', 'trusted.com'];
    try {
        const urlObj = new URL(url);
        return allowedDomains.includes(urlObj.hostname);
    } catch {
        return false;
    }
}

function sanitizeLogData(data) {
    // Remove sensitive fields and mask values
    const { password, creditCard, ...safeData } = data;
    return {
        ...safeData,
        email: data.email ? '***@***.***' : undefined,
        phone: data.phone ? '***-***-****' : undefined
    };
}

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
}); 