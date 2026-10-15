const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'invoease.db');
const db = new sqlite3.Database(DB_PATH);

function initDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // 1. Settings Table
      db.run(`
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT
        )
      `);

      // 2. Users Table
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          email TEXT UNIQUE,
          password TEXT,
          role TEXT DEFAULT 'freelancer',
          business_name TEXT,
          gstin TEXT,
          address TEXT,
          phone TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // 3. Invoices Table
      db.run(`
        CREATE TABLE IF NOT EXISTS invoices (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          invoice_number TEXT,
          client_name TEXT,
          client_email TEXT,
          client_address TEXT,
          client_gstin TEXT,
          items_json TEXT,
          currency TEXT DEFAULT '₹',
          subtotal REAL,
          sgst_rate REAL,
          cgst_rate REAL,
          sgst_amount REAL,
          cgst_amount REAL,
          discount_rate REAL,
          discount_amount REAL,
          grand_total REAL,
          notes TEXT,
          status TEXT DEFAULT 'Pending',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `);

      // 4. Clients Table
      db.run(`
        CREATE TABLE IF NOT EXISTS clients (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          name TEXT,
          email TEXT,
          address TEXT,
          gstin TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // 5. Security Audit Logs Table (A09: Logging & Monitoring)
      db.run(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          ip TEXT,
          user_id INTEGER,
          action TEXT,
          details TEXT,
          status TEXT
        )
      `);

      // Initialize default security mode if not set
      db.get(`SELECT value FROM settings WHERE key = 'security_mode'`, (err, row) => {
        if (!row) {
          // Default to 'lab' so user can immediately test OWASP Top 10 vulnerabilities,
          // with one-click toggle to 'secure' mode.
          db.run(`INSERT INTO settings (key, value) VALUES ('security_mode', 'lab')`);
        }
      });

      // Seed initial users if empty
      db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
        if (err) return reject(err);
        if (row.count === 0) {
          const salt = bcrypt.genSaltSync(10);
          const hashPassword = bcrypt.hashSync('Password123!', salt);

          // Seed user 1: Alice (Freelancer)
          db.run(
            `INSERT INTO users (username, email, password, role, business_name, gstin, address, phone)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            ['alice_dev', 'alice@invoease.local', hashPassword, 'freelancer', 'Alice Web Studio', '27ABCDE1234F1Z5', '123 Tech Park, Bangalore, India', '+91 9876543210'],
            function (err) {
              if (err) return console.error('Error seeding Alice:', err);
              const aliceId = this.lastID;

              // Seed sample invoice for Alice
              const sampleItems1 = JSON.stringify([
                { desc: 'Full-Stack Web App Development', qty: 1, price: 45000 },
                { desc: 'Cloud Infrastructure & CI/CD Setup', qty: 1, price: 15000 }
              ]);
              db.run(
                `INSERT INTO invoices (user_id, invoice_number, client_name, client_email, client_address, client_gstin, items_json, currency, subtotal, sgst_rate, cgst_rate, sgst_amount, cgst_amount, discount_rate, discount_amount, grand_total, notes, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [aliceId, 'INV-2026-001', 'Acme Corporation', 'billing@acme.corp', '45 Commercial Blvd, Mumbai', '27AABCA1122D1Z8', sampleItems1, '₹', 60000, 9, 9, 5400, 5400, 5, 3000, 67800, 'Thank you for your business. Payment due within 15 days.', 'Paid']
              );

              const sampleItems2 = JSON.stringify([
                { desc: 'REST API Optimization & Performance Audit', qty: 1, price: 20000 }
              ]);
              db.run(
                `INSERT INTO invoices (user_id, invoice_number, client_name, client_email, client_address, client_gstin, items_json, currency, subtotal, sgst_rate, cgst_rate, sgst_amount, cgst_amount, discount_rate, discount_amount, grand_total, notes, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [aliceId, 'INV-2026-002', 'Fintech Innovators Ltd', 'finance@fintech.io', '88 Silicon Tower, Hyderabad', '36AACCF9988E1Z2', sampleItems2, '₹', 20000, 9, 9, 1800, 1800, 0, 0, 23600, 'Please transfer to registered bank account.', 'Pending']
              );

              // Seed client for Alice
              db.run(`INSERT INTO clients (user_id, name, email, address, gstin) VALUES (?, ?, ?, ?, ?)`,
                [aliceId, 'Acme Corporation', 'billing@acme.corp', '45 Commercial Blvd, Mumbai', '27AABCA1122D1Z8']
              );
              db.run(`INSERT INTO clients (user_id, name, email, address, gstin) VALUES (?, ?, ?, ?, ?)`,
                [aliceId, 'Fintech Innovators Ltd', 'finance@fintech.io', '88 Silicon Tower, Hyderabad', '36AACCF9988E1Z2']
              );
            }
          );

          // Seed user 2: Bob (Another Freelancer - useful for testing IDOR / Horizontal Privilege Escalation)
          db.run(
            `INSERT INTO users (username, email, password, role, business_name, gstin, address, phone)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            ['bob_designer', 'bob@invoease.local', hashPassword, 'freelancer', 'Bob Creative Designs', '29XYZDE9876K1Z1', '50 Art District, Chennai', '+91 9123456789'],
            function (err) {
              if (err) return console.error('Error seeding Bob:', err);
              const bobId = this.lastID;

              const bobItems = JSON.stringify([
                { desc: 'Confidential Brand Identity Redesign', qty: 1, price: 35000 }
              ]);
              db.run(
                `INSERT INTO invoices (user_id, invoice_number, client_name, client_email, client_address, client_gstin, items_json, currency, subtotal, sgst_rate, cgst_rate, sgst_amount, cgst_amount, discount_rate, discount_amount, grand_total, notes, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [bobId, 'INV-BOB-901', 'Private Client Secret Project', 'secret@client.com', 'Private Address', '29AABCB3344F1Z0', bobItems, '₹', 35000, 9, 9, 3150, 3150, 0, 0, 41300, 'Confidential Invoice - Not for public disclosure', 'Pending']
              );
            }
          );

          // Seed user 3: Admin (useful for testing Vertical Privilege Escalation / A01)
          db.run(
            `INSERT INTO users (username, email, password, role, business_name, gstin, address, phone)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            ['superadmin', 'admin@invoease.local', hashPassword, 'admin', 'InvoEase Platform Admin', '07AAAAA0000A1Z5', 'HQ Tech Park, Delhi', '+91 9999999999']
          );
        }
        resolve();
      });
    });
  });
}

module.exports = { db, initDatabase };
