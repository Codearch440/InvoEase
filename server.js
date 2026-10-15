const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');

const { db, initDatabase } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'invoease-super-secret-key-change-in-prod';

// Ensure uploads folder exists
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer storage for logo uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    // In Lab mode: original name kept (allows path traversal / extension testing)
    // In Secure mode: safe randomized name
    const ext = path.extname(file.originalname);
    const safeName = Date.now() + '-' + Math.round(Math.random() * 1e9) + ext;
    cb(null, safeName);
  }
});
const upload = multer({ storage: storage });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

// Helper to log security events (A09: Logging & Monitoring)
function logSecurityEvent(ip, userId, action, details, status) {
  db.run(
    `INSERT INTO audit_logs (ip, user_id, action, details, status) VALUES (?, ?, ?, ?, ?)`,
    [ip || '127.0.0.1', userId || null, action, details, status || 'INFO']
  );
}

// Helper to get current security mode
function getSecurityMode() {
  return new Promise((resolve) => {
    db.get(`SELECT value FROM settings WHERE key = 'security_mode'`, (err, row) => {
      resolve(row ? row.value : 'lab');
    });
  });
}

// Security Headers Middleware (A05: Security Misconfiguration)
app.use(async (req, res, next) => {
  const mode = await getSecurityMode();
  if (mode === 'secure') {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com;"
    );
  } else {
    // In Lab Mode: security headers intentionally omitted so user can test Clickjacking / missing CSP
    res.removeHeader('X-Frame-Options');
  }
  next();
});

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiter for Login (A07: Identification and Authentication Failures)
const secureLoginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // Limit each IP to 5 requests per windowMs in secure mode
  message: { error: 'Too many login attempts from this IP, please try again after 5 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const dynamicLoginLimiter = async (req, res, next) => {
  const mode = await getSecurityMode();
  if (mode === 'secure') {
    return secureLoginLimiter(req, res, next);
  }
  // In Lab mode: no rate limiting (brute force testing permitted)
  next();
};

// Authentication Middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1];
  if (!token && req.cookies) {
    token = req.cookies.invoease_token;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Please login.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired session token.' });
    }
    req.user = user;
    next();
  });
}

// ==========================================
// 1. SECURITY MODE CONTROLLER & OWASP MATRIX
// ==========================================

// Get current security mode
app.get('/api/security/mode', async (req, res) => {
  const mode = await getSecurityMode();
  res.json({ mode });
});

// Toggle / Set security mode
app.post('/api/security/mode', async (req, res) => {
  const { mode } = req.body;
  if (!['lab', 'secure'].includes(mode)) {
    return res.status(400).json({ error: 'Mode must be "lab" or "secure"' });
  }
  db.run(`UPDATE settings SET value = ? WHERE key = 'security_mode'`, [mode], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    logSecurityEvent(req.ip, req.user ? req.user.id : null, 'SECURITY_MODE_CHANGE', `Mode changed to ${mode.toUpperCase()}`, 'SUCCESS');
    res.json({ success: true, mode });
  });
});

// Detailed OWASP Top 10 Test Matrix Guide
app.get('/api/security/matrix', (req, res) => {
  const matrix = [
    {
      id: 'A01',
      title: 'A01:2021 – Broken Access Control (IDOR & Privilege Escalation)',
      endpoint: 'GET /api/invoices/:id | GET /api/admin/users',
      description: 'Accessing another user\'s invoice (e.g. Invoice #2 belonging to Bob while logged in as Alice) or accessing admin data with a standard freelancer role.',
      labBehavior: 'In Lab Mode, any authenticated user can view/delete any invoice ID regardless of ownership (IDOR), and non-admins can view user listings.',
      secureBehavior: 'In Secure Mode, object-level authorization strictly verifies user_id === invoice.user_id, and admin routes enforce role === "admin".',
      testHint: 'Login as Alice (user ID 1), then fetch invoice ID 2 (belongs to Bob). Observe IDOR in Lab vs 403 Forbidden in Secure.'
    },
    {
      id: 'A02',
      title: 'A02:2021 – Cryptographic Failures',
      endpoint: 'POST /api/auth/login | Cookies',
      description: 'Handling of sensitive data and session cookies.',
      labBehavior: 'Cookies sent without HttpOnly or Secure flags; sensitive password hash exposures.',
      secureBehavior: 'Cookies set with HttpOnly, SameSite=Strict; Bcrypt 10 rounds; passwords never exposed.',
      testHint: 'Inspect document.cookie in browser console; observe session token accessible via JavaScript in Lab mode.'
    },
    {
      id: 'A03',
      title: 'A03:2021 – Injection (SQL Injection & Stored XSS)',
      endpoint: 'GET /api/invoices?search=... | POST /api/invoices',
      description: 'SQL queries constructed with string concatenation in search; Unsanitized HTML rendering in invoice notes/items.',
      labBehavior: 'Search parameter concatenated directly into SQL statement. Raw HTML injected into preview template.',
      secureBehavior: 'Parameterized SQL queries (prepared statements). Proper HTML escaping / textContent rendering.',
      testHint: 'Test search query with \' OR 1=1 -- in Lab mode to see all invoices bypassed. In invoice notes, input <script> or <img onerror>.'
    },
    {
      id: 'A04',
      title: 'A04:2021 – Insecure Design (Business Logic Flaws)',
      endpoint: 'POST /api/invoices',
      description: 'Client-side manipulation of calculations: negative line-item quantities, negative prices, or 200% discounts.',
      labBehavior: 'Server blindly accepts client-calculated totals and allows negative quantities or excessive discounts.',
      secureBehavior: 'Server authoritatively validates items, quantities (>0), discounts (0-100%), and recalculates GST and grand total.',
      testHint: 'Submit an invoice with quantity: -5 or discount: 150. Notice how Lab mode saves negative grand total.'
    },
    {
      id: 'A05',
      title: 'A05:2021 – Security Misconfiguration',
      endpoint: 'GET /api/debug/environment | HTTP Headers',
      description: 'Verbose error messages, debug endpoints, missing security headers (CSP, X-Frame-Options).',
      labBehavior: 'Debug endpoint exposes system environment variables; missing X-Frame-Options allows clickjacking testing.',
      secureBehavior: 'Debug endpoint disabled; strict CSP, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff enforced.',
      testHint: 'Visit /api/debug/environment or test iframe embedding in an external page.'
    },
    {
      id: 'A06',
      title: 'A06:2021 – Vulnerable and Outdated Components',
      endpoint: 'GET /api/system/dependencies',
      description: 'Visibility into third-party dependencies and supply chain risks.',
      labBehavior: 'Public endpoint reveals exact npm package versions.',
      secureBehavior: 'Dependency information restricted to authenticated system administrators.',
      testHint: 'Query /api/system/dependencies to audit third-party libraries.'
    },
    {
      id: 'A07',
      title: 'A07:2021 – Identification & Authentication Failures',
      endpoint: 'POST /api/auth/login',
      description: 'Brute-force password guessing and username enumeration.',
      labBehavior: 'No rate limiting, distinct error messages ("User does not exist" vs "Incorrect password") facilitating enumeration.',
      secureBehavior: 'Rate-limiting active (max 5 attempts per 5 mins), uniform error message ("Invalid username or password").',
      testHint: 'Test invalid username vs invalid password in Lab mode to observe credential enumeration.'
    },
    {
      id: 'A08',
      title: 'A08:2021 – Software and Data Integrity Failures',
      endpoint: 'POST /api/upload/logo',
      description: 'Unrestricted file upload for company invoice logo without strict MIME type validation.',
      labBehavior: 'Allows uploading arbitrary file types and executing/viewing them from public/uploads.',
      secureBehavior: 'Strictly whitelists images (image/png, image/jpeg, image/webp) and enforces file size limits.',
      testHint: 'Upload a non-image file (e.g. .html or .txt) in Lab mode vs Secure mode.'
    },
    {
      id: 'A09:2021',
      title: 'A09:2021 – Security Logging & Monitoring Failures',
      endpoint: 'GET /api/security/logs',
      description: 'Failure to record critical security actions and access anomalies.',
      labBehavior: 'Failed logins, privilege escalation, and invoice deletions are not logged to the audit trail.',
      secureBehavior: 'Comprehensive audit trail tracks every login attempt, role modification, deletion, and mode change with IP.',
      testHint: 'Check /api/security/logs after actions to observe logging coverage.'
    },
    {
      id: 'A10',
      title: 'A10:2021 – Server-Side Request Forgery (SSRF)',
      endpoint: 'POST /api/fetch-remote-logo',
      description: 'Server fetches remote company logo by URL provided by the user.',
      labBehavior: 'Server blindly issues HTTP/HTTPS requests to internal IPs (e.g. 127.0.0.1, 169.254.169.254, localhost:3000).',
      secureBehavior: 'Validates protocol (http/https only) and rejects private IP ranges (RFC 1918, localhost, loopback).',
      testHint: 'Send a request with url="http://127.0.0.1:3000/api/security/mode" to observe server-side fetching.'
    }
  ];
  res.json(matrix);
});

// ==========================================
// 2. AUTHENTICATION (A07 & A01)
// ==========================================

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, role, business_name, gstin, address, phone } = req.body;
  const mode = await getSecurityMode();

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required.' });
  }

  // In Secure Mode: enforce password policy & prevent mass assignment of role
  let assignedRole = 'freelancer';
  if (mode === 'lab') {
    // A01 / Mass assignment vulnerability in Lab mode: user can supply "role: 'admin'"!
    if (role) assignedRole = role;
  } else {
    // In Secure mode: password complexity check
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }
  }

  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  db.run(
    `INSERT INTO users (username, email, password, role, business_name, gstin, address, phone)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [username, email, hashedPassword, assignedRole, business_name || '', gstin || '', address || '', phone || ''],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message.includes('UNIQUE') ? 'Username or email already exists.' : err.message });
      }
      logSecurityEvent(req.ip, this.lastID, 'USER_REGISTER', `New user registered: ${username} with role ${assignedRole}`, 'SUCCESS');
      res.status(201).json({ success: true, message: 'Registration successful! You can now log in.' });
    }
  );
});

// Login
app.post('/api/auth/login', dynamicLoginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const mode = await getSecurityMode();

  if (!username || !password) {
    return res.status(400).json({ error: 'Please enter both username and password.' });
  }

  db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error.' });

    // A07: Username enumeration difference in Lab mode
    if (!user) {
      logSecurityEvent(req.ip, null, 'LOGIN_FAILED', `Non-existent user attempt: ${username}`, 'FAIL');
      if (mode === 'lab') {
        return res.status(401).json({ error: 'User does not exist.' }); // Leaks user presence!
      } else {
        return res.status(401).json({ error: 'Invalid username or password.' }); // Generic message
      }
    }

    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      logSecurityEvent(req.ip, user.id, 'LOGIN_FAILED', `Incorrect password for user: ${username}`, 'FAIL');
      if (mode === 'lab') {
        return res.status(401).json({ error: 'Incorrect password.' }); // Leaks user presence!
      } else {
        return res.status(401).json({ error: 'Invalid username or password.' });
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    // A02 / A05: Cookie configuration
    if (mode === 'secure') {
      res.cookie('invoease_token', token, {
        httpOnly: true, // Prevents XSS token theft
        sameSite: 'strict',
        maxAge: 12 * 60 * 60 * 1000
      });
    } else {
      // In Lab mode: cookie lacks HttpOnly flag, allowing document.cookie reading via XSS
      res.cookie('invoease_token', token, {
        httpOnly: false,
        maxAge: 12 * 60 * 60 * 1000
      });
    }

    logSecurityEvent(req.ip, user.id, 'LOGIN_SUCCESS', `User logged in: ${user.username}`, 'SUCCESS');

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        business_name: user.business_name,
        gstin: user.gstin,
        address: user.address,
        phone: user.phone
      }
    });
  });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('invoease_token');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Current user profile
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get(
    `SELECT id, username, email, role, business_name, gstin, address, phone, created_at FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found.' });
      res.json({ user });
    }
  );
});

// Update Profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  const { business_name, gstin, address, phone, email } = req.body;
  db.run(
    `UPDATE users SET business_name = ?, gstin = ?, address = ?, phone = ?, email = ? WHERE id = ?`,
    [business_name, gstin, address, phone, email, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: 'Profile updated successfully.' });
    }
  );
});

// ==========================================
// 3. INVOICE MANAGEMENT (A01, A03, A04)
// ==========================================

// Get Invoices list
app.get('/api/invoices', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();
  const search = req.query.search || '';
  const status = req.query.status || '';

  if (mode === 'lab') {
    // A03: SQL Injection Vulnerability in Lab Mode!
    // Directly concatenates search input into SQL query for manual SQLi testing
    let query = `SELECT * FROM invoices WHERE 1=1`;
    if (search) {
      query += ` AND (client_name LIKE '%${search}%' OR invoice_number LIKE '%${search}%')`;
    }
    if (status) {
      query += ` AND status = '${status}'`;
    }
    // Note: In lab mode, if user doesn't pass search injection, we still scope or show user's invoices
    if (!search && req.user.role !== 'admin') {
      query += ` AND user_id = ${req.user.id}`;
    }
    query += ` ORDER BY id DESC`;

    db.all(query, (err, rows) => {
      if (err) {
        // A05: Security Misconfiguration - Verbose DB error disclosure
        return res.status(500).json({ error: 'SQL Execution Error: ' + err.message, query });
      }
      res.json({ invoices: rows || [] });
    });
  } else {
    // Secure Mode: Parameterized SQL Query with strict ownership check
    let query = `SELECT * FROM invoices WHERE user_id = ?`;
    const params = [req.user.id];

    if (search) {
      query += ` AND (client_name LIKE ? OR invoice_number LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }
    if (status) {
      query += ` AND status = ?`;
      params.push(status);
    }
    query += ` ORDER BY id DESC`;

    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to retrieve invoices.' });
      res.json({ invoices: rows || [] });
    });
  }
});

// Get Single Invoice by ID (A01: IDOR testing)
app.get('/api/invoices/:id', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();
  const invoiceId = req.params.id;

  db.get(`SELECT * FROM invoices WHERE id = ?`, [invoiceId], (err, invoice) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!invoice) return res.status(404).json({ error: 'Invoice not found.' });

    if (mode === 'lab') {
      // A01: IDOR in Lab mode! Any authenticated user can view another user's invoice!
      return res.json({ invoice });
    } else {
      // Secure Mode: Object-Level Authorization Check
      if (invoice.user_id !== req.user.id && req.user.role !== 'admin') {
        logSecurityEvent(req.ip, req.user.id, 'UNAUTHORIZED_INVOICE_ACCESS', `Attempted access to Invoice #${invoiceId}`, 'BLOCKED');
        return res.status(403).json({ error: 'Access Denied: You do not have permission to view this invoice.' });
      }
      return res.json({ invoice });
    }
  });
});

// Create Invoice (A04: Insecure Design & A03: Stored XSS)
app.post('/api/invoices', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();
  let {
    client_name,
    client_email,
    client_address,
    client_gstin,
    items,
    currency,
    sgst_rate,
    cgst_rate,
    discount_rate,
    notes,
    status
  } = req.body;

  if (!client_name || !items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Client name and at least one item are required.' });
  }

  let subtotal = 0;
  let parsedSgstRate = parseFloat(sgst_rate) || 0;
  let parsedCgstRate = parseFloat(cgst_rate) || 0;
  let parsedDiscountRate = parseFloat(discount_rate) || 0;

  if (mode === 'lab') {
    // In Lab Mode: Allows negative rates/amounts and accepts client calculations (A04)
    items.forEach((item) => {
      const q = parseFloat(item.qty) || 0;
      const p = parseFloat(item.price) || 0;
      subtotal += q * p;
    });
  } else {
    // In Secure Mode: Validates positive values and range constraints
    for (const item of items) {
      const q = parseFloat(item.qty);
      const p = parseFloat(item.price);
      if (isNaN(q) || q <= 0 || isNaN(p) || p < 0) {
        return res.status(400).json({ error: 'All line item quantities must be > 0 and prices >= 0.' });
      }
      subtotal += q * p;
    }
    if (parsedDiscountRate < 0 || parsedDiscountRate > 100) {
      return res.status(400).json({ error: 'Discount rate must be between 0% and 100%.' });
    }
    if (parsedSgstRate < 0 || parsedCgstRate < 0) {
      return res.status(400).json({ error: 'GST rates cannot be negative.' });
    }
  }

  const sgst_amount = (subtotal * parsedSgstRate) / 100;
  const cgst_amount = (subtotal * parsedCgstRate) / 100;
  const discount_amount = (subtotal * parsedDiscountRate) / 100;
  const grand_total = subtotal + sgst_amount + cgst_amount - discount_amount;

  const invoiceNumber = 'INV-' + Date.now().toString().slice(-6);

  db.run(
    `INSERT INTO invoices (
      user_id, invoice_number, client_name, client_email, client_address, client_gstin,
      items_json, currency, subtotal, sgst_rate, cgst_rate, sgst_amount, cgst_amount,
      discount_rate, discount_amount, grand_total, notes, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      req.user.id,
      invoiceNumber,
      client_name,
      client_email || '',
      client_address || '',
      client_gstin || '',
      JSON.stringify(items),
      currency || '₹',
      subtotal,
      parsedSgstRate,
      parsedCgstRate,
      sgst_amount,
      cgst_amount,
      parsedDiscountRate,
      discount_amount,
      grand_total,
      notes || '',
      status || 'Pending'
    ],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      logSecurityEvent(req.ip, req.user.id, 'INVOICE_CREATED', `Invoice ${invoiceNumber} created for ${client_name}`, 'SUCCESS');
      res.status(201).json({
        success: true,
        invoice_id: this.lastID,
        invoice_number: invoiceNumber,
        grand_total
      });
    }
  );
});

// Update Invoice Status
app.put('/api/invoices/:id/status', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();
  const { status } = req.body;
  const invoiceId = req.params.id;

  if (!['Paid', 'Pending', 'Overdue', 'Draft'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }

  if (mode === 'lab') {
    // In Lab Mode: Can update any invoice status without ownership check
    db.run(`UPDATE invoices SET status = ? WHERE id = ?`, [status, invoiceId], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: 'Status updated.' });
    });
  } else {
    // In Secure Mode: Enforces ownership
    db.run(`UPDATE invoices SET status = ? WHERE id = ? AND user_id = ?`, [status, invoiceId, req.user.id], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Invoice not found or unauthorized.' });
      res.json({ success: true, message: 'Status updated.' });
    });
  }
});

// Delete Invoice (A01: IDOR)
app.delete('/api/invoices/:id', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();
  const invoiceId = req.params.id;

  if (mode === 'lab') {
    // A01: IDOR Delete in Lab Mode!
    db.run(`DELETE FROM invoices WHERE id = ?`, [invoiceId], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      logSecurityEvent(req.ip, req.user.id, 'INVOICE_DELETED', `Invoice #${invoiceId} deleted without ownership verification (LAB)`, 'SUCCESS');
      res.json({ success: true, message: `Invoice #${invoiceId} deleted.` });
    });
  } else {
    // Secure Mode: Checks ownership
    db.run(`DELETE FROM invoices WHERE id = ? AND user_id = ?`, [invoiceId, req.user.id], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(403).json({ error: 'Access Denied: You cannot delete this invoice.' });
      logSecurityEvent(req.ip, req.user.id, 'INVOICE_DELETED', `Invoice #${invoiceId} deleted by owner`, 'SUCCESS');
      res.json({ success: true, message: `Invoice #${invoiceId} deleted.` });
    });
  }
});

// ==========================================
// 4. CLIENTS MANAGEMENT
// ==========================================
app.get('/api/clients', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM clients WHERE user_id = ? ORDER BY name ASC`, [req.user.id], (err, clients) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ clients: clients || [] });
  });
});

app.post('/api/clients', authenticateToken, (req, res) => {
  const { name, email, address, gstin } = req.body;
  if (!name) return res.status(400).json({ error: 'Client name is required.' });

  db.run(
    `INSERT INTO clients (user_id, name, email, address, gstin) VALUES (?, ?, ?, ?, ?)`,
    [req.user.id, name, email || '', address || '', gstin || ''],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ success: true, client_id: this.lastID, name });
    }
  );
});

// ==========================================
// 5. ADMIN & PRIVILEGE ESCALATION (A01)
// ==========================================
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();

  if (mode === 'lab') {
    // A01: Vertical Privilege Escalation Flaw in Lab Mode!
    // Fails to check if role === 'admin', exposes all user records to any authenticated user!
    db.all(`SELECT id, username, email, role, business_name, gstin, created_at FROM users`, (err, users) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ users });
    });
  } else {
    // Secure Mode: Strict role-based authorization
    if (req.user.role !== 'admin') {
      logSecurityEvent(req.ip, req.user.id, 'ADMIN_ACCESS_BLOCKED', 'Non-admin user tried accessing /api/admin/users', 'BLOCKED');
      return res.status(403).json({ error: 'Forbidden: Admin privileges required.' });
    }
    db.all(`SELECT id, username, email, role, business_name, gstin, created_at FROM users`, (err, users) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ users });
    });
  }
});

// ==========================================
// 6. SSRF ENDPOINT (A10)
// ==========================================
app.post('/api/fetch-remote-logo', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required.' });
  }

  if (mode === 'lab') {
    // A10: SSRF in Lab Mode! Server blindly requests the URL without validation
    try {
      const parsedUrl = new URL(url);
      const clientModule = parsedUrl.protocol === 'https:' ? https : http;

      const request = clientModule.get(url, { timeout: 3000 }, (remoteRes) => {
        let data = '';
        remoteRes.on('data', (chunk) => {
          if (data.length < 50000) data += chunk; // cap response size
        });
        remoteRes.on('end', () => {
          res.json({
            success: true,
            status: remoteRes.statusCode,
            headers: remoteRes.headers,
            dataPreview: data.slice(0, 1000)
          });
        });
      });

      request.on('error', (err) => {
        res.status(500).json({ error: 'Remote request failed: ' + err.message });
      });
    } catch (e) {
      res.status(400).json({ error: 'Invalid URL: ' + e.message });
    }
  } else {
    // Secure Mode: SSRF Protection
    try {
      const parsedUrl = new URL(url);

      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return res.status(400).json({ error: 'Only HTTP and HTTPS protocols are allowed.' });
      }

      const hostname = parsedUrl.hostname.toLowerCase();
      // Block localhost, loopback, private ranges (RFC 1918), AWS/cloud metadata (169.254.169.254)
      if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '::1' ||
        hostname.startsWith('10.') ||
        hostname.startsWith('192.168.') ||
        (hostname.startsWith('172.') && parseInt(hostname.split('.')[1], 10) >= 16 && parseInt(hostname.split('.')[1], 10) <= 31) ||
        hostname === '169.254.169.254'
      ) {
        logSecurityEvent(req.ip, req.user.id, 'SSRF_ATTEMPT_BLOCKED', `Blocked attempt to access internal host: ${hostname}`, 'BLOCKED');
        return res.status(403).json({ error: 'Access Denied: Requests to private, local, or cloud metadata IP addresses are strictly prohibited.' });
      }

      res.json({
        success: true,
        message: 'URL passed security checks. Safe to fetch remote asset.',
        verifiedUrl: url
      });
    } catch (e) {
      res.status(400).json({ error: 'Invalid URL format.' });
    }
  }
});

// ==========================================
// 7. FILE UPLOAD (A08: Data Integrity)
// ==========================================
app.post('/api/upload/logo', authenticateToken, upload.single('logo'), async (req, res) => {
  const mode = await getSecurityMode();

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  if (mode === 'lab') {
    // In Lab Mode: Accepts any file extension (HTML, JS, SVG, EXE) without MIME validation
    res.json({
      success: true,
      filename: req.file.filename,
      filePath: `/uploads/${req.file.filename}`,
      mimeType: req.file.mimetype
    });
  } else {
    // Secure Mode: Whitelist image MIME types and enforce extension check
    const allowedMime = ['image/png', 'image/jpeg', 'image/webp'];
    const ext = path.extname(req.file.originalname).toLowerCase();
    const allowedExts = ['.png', '.jpg', '.jpeg', '.webp'];

    if (!allowedMime.includes(req.file.mimetype) || !allowedExts.includes(ext)) {
      // Clean up unsafe file
      try { fs.unlinkSync(req.file.path); } catch (e) {}
      logSecurityEvent(req.ip, req.user.id, 'UNSAFE_FILE_UPLOAD_BLOCKED', `Blocked upload: ${req.file.originalname} (${req.file.mimetype})`, 'BLOCKED');
      return res.status(400).json({ error: 'File validation failed: Only PNG, JPEG, and WebP images are allowed.' });
    }

    res.json({
      success: true,
      filename: req.file.filename,
      filePath: `/uploads/${req.file.filename}`,
      message: 'File passed integrity checks.'
    });
  }
});

// ==========================================
// 8. SECURITY MISCONFIGURATION & DEBUG (A05)
// ==========================================
app.get('/api/debug/environment', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();

  if (mode === 'lab') {
    // A05: Sensitive environment & configuration disclosure
    res.json({
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      uptime_seconds: process.uptime(),
      memory_usage: process.memoryUsage(),
      env_preview: {
        PORT: PORT,
        JWT_SECRET_CONFIGURED: true,
        NODE_ENV: process.env.NODE_ENV || 'development'
      }
    });
  } else {
    // In Secure mode: endpoint disabled
    res.status(404).json({ error: 'Debug endpoints are disabled in production/secure mode.' });
  }
});

// Dependency audit check (A06)
app.get('/api/system/dependencies', authenticateToken, async (req, res) => {
  const mode = await getSecurityMode();
  if (mode === 'secure' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access restricted to system administrators.' });
  }

  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    res.json({
      name: pkg.name,
      version: pkg.version,
      dependencies: pkg.dependencies
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to read package information.' });
  }
});

// ==========================================
// 9. AUDIT LOGS & MONITORING (A09)
// ==========================================
app.get('/api/security/logs', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50`, (err, logs) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ logs: logs || [] });
  });
});

// Start Server after database is ready
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🚀 InvoEase Pro is running on http://localhost:${PORT}`);
    console.log(`🛡️  OWASP Top 10 Manual Testing Lab is ACTIVE`);
    console.log(`====================================================`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
});
