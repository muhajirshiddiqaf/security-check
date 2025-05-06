const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Create in-memory database
const db = new sqlite3.Database(':memory:');

// Initialize database with tables and sample data
async function initializeDatabase() {
    return new Promise((resolve, reject) => {
        // Create tables
        db.serialize(() => {
            // Users table
            db.run(`CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT,
                role TEXT,
                isAdmin INTEGER DEFAULT 0,
                apiKey TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);

            // Comments table
            db.run(`CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT,
                user_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )`);

            // Products table
            db.run(`CREATE TABLE products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                price REAL,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);

            // Orders table
            db.run(`CREATE TABLE orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                total_amount REAL,
                status TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )`);

            // Insert sample data
            const insertUsers = db.prepare(`INSERT INTO users (username, password, email, role, isAdmin, apiKey) VALUES (?, ?, ?, ?, ?, ?)`);
            
            // Create hashed passwords
            const adminPassword = bcrypt.hashSync('admin123', 10);
            const userPassword = bcrypt.hashSync('user123', 10);
            const guestPassword = bcrypt.hashSync('guest123', 10);

            // Insert users
            insertUsers.run('admin', adminPassword, 'admin@example.com', 'admin', 1, 'admin-api-key-123');
            insertUsers.run('user', userPassword, 'user@example.com', 'user', 0, 'user-api-key-456');
            insertUsers.run('guest', guestPassword, 'guest@example.com', 'guest', 0, 'guest-api-key-789');
            insertUsers.finalize();

            // Insert comments
            const insertComments = db.prepare(`INSERT INTO comments (content, user_id) VALUES (?, ?)`);
            insertComments.run('This is a normal comment', 1);
            insertComments.run('Another comment from user', 2);
            insertComments.run('<script>alert("XSS Attack")</script>', 3); // XSS payload
            insertComments.finalize();

            // Insert products
            const insertProducts = db.prepare(`INSERT INTO products (name, price, description) VALUES (?, ?, ?)`);
            insertProducts.run('Product 1', 99.99, 'Description for product 1');
            insertProducts.run('Product 2', 149.99, 'Description for product 2');
            insertProducts.run('Product 3', 199.99, 'Description for product 3');
            insertProducts.finalize();

            // Insert orders
            const insertOrders = db.prepare(`INSERT INTO orders (user_id, total_amount, status) VALUES (?, ?, ?)`);
            insertOrders.run(1, 299.98, 'completed');
            insertOrders.run(2, 149.99, 'pending');
            insertOrders.run(3, 99.99, 'processing');
            insertOrders.finalize();

            resolve();
        });
    });
}

// Database queries
const dbQueries = {
    // User queries
    getUserByUsername: (username) => {
        return new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    },

    updateUser: (id, updates) => {
        return new Promise((resolve, reject) => {
            const fields = Object.keys(updates);
            const values = Object.values(updates);
            const setClause = fields.map(field => `${field} = ?`).join(', ');
            
            db.run(`UPDATE users SET ${setClause} WHERE id = ?`, [...values, id], function(err) {
                if (err) reject(err);
                else resolve(this.changes);
            });
        });
    },

    // Comment queries
    getComments: () => {
        return new Promise((resolve, reject) => {
            db.all('SELECT * FROM comments', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    },

    addComment: (content, userId) => {
        return new Promise((resolve, reject) => {
            db.run('INSERT INTO comments (content, user_id) VALUES (?, ?)', [content, userId], function(err) {
                if (err) reject(err);
                else resolve(this.lastID);
            });
        });
    },

    // Product queries
    getProducts: () => {
        return new Promise((resolve, reject) => {
            db.all('SELECT * FROM products', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    },

    // Order queries
    getOrders: () => {
        return new Promise((resolve, reject) => {
            db.all('SELECT * FROM orders', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }
};

module.exports = { db, initializeDatabase, dbQueries }; 