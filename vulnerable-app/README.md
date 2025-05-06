# Web Security Learning Platform

Platform pembelajaran keamanan web yang mendemonstrasikan berbagai kerentanan umum dan implementasi amannya.

## Daftar Isi
1. [Input Attacks](#input-attacks)
2. [Authentication Attacks](#authentication-attacks)
3. [Data Exposure and Client-Side](#data-exposure-and-client-side)
4. [Defense 101](#defense-101)
5. [Common Vulnerabilities](#common-vulnerabilities)

## Input Attacks

### 1. SQL Injection
**Deskripsi**: Serangan yang memanipulasi query SQL melalui input pengguna.

**Contoh Rentan**:
```javascript
// Vulnerable
app.get('/api/vulnerable/search', (req, res) => {
    const query = req.query.q;
    db.all(`SELECT * FROM users WHERE username LIKE '%${query}%'`, (err, rows) => {
        res.json(rows);
    });
});
```

**Contoh Aman**:
```javascript
// Secure
app.get('/api/secure/search', (req, res) => {
    const query = req.query.q;
    db.all(`SELECT * FROM users WHERE username LIKE ?`, [`%${query}%`], (err, rows) => {
        res.json(rows);
    });
});
```

**Cara Test**:
1. Masukkan `' OR '1'='1` pada form pencarian
2. Masukkan `'; DROP TABLE users; --` untuk mencoba menghapus tabel

### 2. XSS (Cross-Site Scripting)
**Deskripsi**: Serangan yang menyisipkan kode JavaScript berbahaya ke dalam halaman web.

**Contoh Rentan**:
```javascript
// Vulnerable
app.post('/api/vulnerable/comments', (req, res) => {
    const { content } = req.body;
    res.json({ content }); // No sanitization
});
```

**Contoh Aman**:
```javascript
// Secure
function sanitizeHTML(str) {
    return str.replace(/[<>]/g, '');
}

app.post('/api/secure/comments', (req, res) => {
    const { content } = req.body;
    res.json({ content: sanitizeHTML(content) });
});
```

**Cara Test**:
1. Masukkan `<script>alert('XSS')</script>` pada form komentar
2. Masukkan `<img src="x" onerror="alert('XSS')">`

### 3. Command Injection
**Deskripsi**: Serangan yang memanipulasi perintah sistem melalui input pengguna.

**Contoh Rentan**:
```javascript
// Vulnerable
app.post('/api/vulnerable/execute', (req, res) => {
    const { command } = req.body;
    exec(command, (error, stdout) => {
        res.json({ output: stdout });
    });
});
```

**Contoh Aman**:
```javascript
// Secure
app.post('/api/secure/execute', (req, res) => {
    const { command } = req.body;
    const allowedCommands = ['ls', 'pwd', 'date'];
    if (!allowedCommands.includes(command)) {
        return res.status(400).json({ error: 'Invalid command' });
    }
    exec(command, (error, stdout) => {
        res.json({ output: stdout });
    });
});
```

**Cara Test**:
1. Masukkan `ls; rm -rf /` pada form command
2. Masukkan `pwd; cat /etc/passwd`

## Authentication Attacks

### 1. Broken Authentication
**Deskripsi**: Kerentanan dalam mekanisme autentikasi yang memungkinkan bypass login.

**Contoh Rentan**:
```javascript
// Vulnerable
app.post('/api/vulnerable/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'admin123') {
        res.json({ token: 'dummy-token' });
    }
});
```

**Contoh Aman**:
```javascript
// Secure
app.post('/api/secure/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.getUser(username);
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
        res.json({ token });
    }
});
```

### 2. Token Theft
**Deskripsi**: Pencurian token autentikasi untuk mengakses akun pengguna.

**Contoh Rentan**:
```javascript
// Vulnerable
localStorage.setItem('token', response.token);
```

**Contoh Aman**:
```javascript
// Secure
document.cookie = `token=${response.token}; HttpOnly; Secure; SameSite=Strict`;
```

### 3. Session Fixation
**Deskripsi**: Serangan yang memaksa pengguna menggunakan session ID yang sudah diketahui penyerang.

**Contoh Rentan**:
```javascript
// Vulnerable
app.post('/login', (req, res) => {
    const sessionId = req.cookies.sessionId;
    // Using provided session ID without regeneration
});
```

**Contoh Aman**:
```javascript
// Secure
app.post('/login', (req, res) => {
    const newSessionId = crypto.randomBytes(32).toString('hex');
    res.cookie('sessionId', newSessionId, {
        httpOnly: true,
        secure: true
    });
});
```

## Data Exposure and Client-Side

### 1. Sensitive Info Leaks
**Deskripsi**: Kebocoran informasi sensitif melalui response API atau error messages.

**Contoh Rentan**:
```javascript
// Vulnerable
app.get('/api/user/:id', (req, res) => {
    const user = db.getUser(req.params.id);
    res.json(user); // Exposes all user data
});
```

**Contoh Aman**:
```javascript
// Secure
app.get('/api/user/:id', (req, res) => {
    const user = db.getUser(req.params.id);
    const { password, ...safeUser } = user;
    res.json(safeUser);
});
```

### 2. CSRF Basics
**Deskripsi**: Serangan yang memaksa pengguna melakukan aksi yang tidak diinginkan.

**Contoh Rentan**:
```javascript
// Vulnerable
app.post('/api/transfer', (req, res) => {
    const { amount, to } = req.body;
    // No CSRF protection
});
```

**Contoh Aman**:
```javascript
// Secure
app.post('/api/transfer', (req, res) => {
    const csrfToken = req.headers['x-csrf-token'];
    if (csrfToken !== req.session.csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    // Process transfer
});
```

### 3. Insecure API Exposures
**Deskripsi**: API yang mengekspos endpoint atau data yang seharusnya tidak publik.

**Contoh Rentan**:
```javascript
// Vulnerable
app.get('/api/admin/users', (req, res) => {
    // No authentication check
    res.json(db.getAllUsers());
});
```

**Contoh Aman**:
```javascript
// Secure
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    res.json(db.getAllUsers());
});
```

## Defense 101

### 1. Validate Inputs
**Deskripsi**: Validasi semua input pengguna sebelum diproses.

**Contoh**:
```javascript
const validateUserInput = (input) => {
    if (typeof input !== 'string') return false;
    if (input.length > 100) return false;
    return /^[a-zA-Z0-9]+$/.test(input);
};
```

### 2. Sanitize Outputs
**Deskripsi**: Membersihkan output sebelum ditampilkan ke pengguna.

**Contoh**:
```javascript
const sanitizeOutput = (str) => {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
};
```

### 3. Safe Auth Flows
**Deskripsi**: Implementasi alur autentikasi yang aman.

**Contoh**:
```javascript
const safeAuthFlow = async (req, res) => {
    const { username, password } = req.body;
    
    // Rate limiting
    if (await isRateLimited(req.ip)) {
        return res.status(429).json({ error: 'Too many attempts' });
    }
    
    // Validate input
    if (!validateCredentials(username, password)) {
        return res.status(400).json({ error: 'Invalid input' });
    }
    
    // Check credentials
    const user = await db.getUser(username);
    if (!user || !await bcrypt.compare(password, user.password)) {
        await incrementFailedAttempts(req.ip);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate session
    const sessionId = await generateSecureSession();
    res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
    });
};
```

### 4. Authorization > Authentication
**Deskripsi**: Memastikan otorisasi yang tepat setelah autentikasi.

**Contoh**:
```javascript
const checkAuthorization = async (req, res, next) => {
    const user = await db.getUser(req.user.id);
    if (!user.hasPermission(req.path, req.method)) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    next();
};
```

## Common Vulnerabilities

### 1. API Mass Assignment
**Risiko**: Escalation privilege, data tampering
**Mitigasi**: Validasi input secara eksplisit
**Contoh**:
```javascript
// Vulnerable
app.put('/api/users/:id', (req, res) => {
    db.updateUser(req.params.id, req.body); // Accepts all fields
});

// Secure
app.put('/api/users/:id', (req, res) => {
    const allowedFields = ['name', 'email'];
    const updates = Object.keys(req.body)
        .filter(key => allowedFields.includes(key))
        .reduce((obj, key) => {
            obj[key] = req.body[key];
            return obj;
        }, {});
    db.updateUser(req.params.id, updates);
});
```

### 2. Integer Overflow
**Risiko**: Miscalculation, buffer overflow
**Mitigasi**: Validasi range nilai
**Contoh**:
```javascript
// Vulnerable
const calculateTotal = (quantity, price) => {
    return quantity * price; // No overflow check
};

// Secure
const calculateTotal = (quantity, price) => {
    if (quantity > Number.MAX_SAFE_INTEGER / price) {
        throw new Error('Integer overflow');
    }
    return quantity * price;
};
```

### 3. SQL Injection (Blind)
**Risiko**: Data exposure, unauthorized access
**Mitigasi**: Parameterized queries
**Contoh**:
```javascript
// Vulnerable
app.get('/api/search', (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
    db.all(query, (err, rows) => res.json(rows));
});

// Secure
app.get('/api/search', (req, res) => {
    db.all('SELECT * FROM users WHERE id = ?', [req.query.id], 
        (err, rows) => res.json(rows));
});
```

## Cara Menjalankan Aplikasi

1. Install dependencies:
```bash
cd vulnerable-app/backend
npm install
```

2. Jalankan server:
```bash
node server.js
```

3. Buka browser dan akses:
```
http://localhost:3000
```

## Kredensial Test

- Admin: username: `admin`, password: `admin123`
- User: username: `user`, password: `user123`

## Catatan Penting

Aplikasi ini dibuat untuk tujuan pembelajaran. Jangan gunakan kode rentan dalam produksi. Selalu implementasikan praktik keamanan terbaik dalam aplikasi produksi. 