/**
 * Barangay Resident Management System
 * Self-contained single-file Node.js, Express, and PostgreSQL application.
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const QRCode = require('qrcode');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Connection Pool using DATABASE_URL (Render compatible)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'brgy-super-secret-key-change-it',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  }
}));

// --- SAFE DATABASE SCHEMA INITIALIZATION ---
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'staff', 'resident')),
        status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'disabled')),
        force_password_change BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Residents table
    await client.query(`
      CREATE TABLE IF NOT EXISTS residents (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        resident_id VARCHAR(50) UNIQUE NOT NULL,
        full_name VARCHAR(150) NOT NULL,
        birthdate DATE NOT NULL,
        sex VARCHAR(20) NOT NULL,
        civil_status VARCHAR(50) NOT NULL,
        address TEXT NOT NULL,
        contact_number VARCHAR(30) NOT NULL,
        email VARCHAR(100),
        occupation VARCHAR(100),
        educational_attainment VARCHAR(100),
        nationality VARCHAR(50) DEFAULT 'Filipino',
        voter_status VARCHAR(20) DEFAULT 'No',
        pwd_status VARCHAR(20) DEFAULT 'No',
        senior_citizen_status VARCHAR(20) DEFAULT 'No',
        four_ps_status VARCHAR(20) DEFAULT 'No',
        emergency_contact TEXT,
        qr_code TEXT,
        is_archived BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Households table
    await client.query(`
      CREATE TABLE IF NOT EXISTS households (
        id SERIAL PRIMARY KEY,
        household_number VARCHAR(50) UNIQUE NOT NULL,
        household_head_id INT REFERENCES residents(id) ON DELETE SET NULL,
        address TEXT NOT NULL,
        classification VARCHAR(50) DEFAULT 'Regular',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Document Requests table
    await client.query(`
      CREATE TABLE IF NOT EXISTS document_requests (
        id SERIAL PRIMARY KEY,
        request_id VARCHAR(50) UNIQUE NOT NULL,
        resident_id INT REFERENCES residents(id) ON DELETE CASCADE,
        document_type VARCHAR(100) NOT NULL,
        purpose TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'Pending' CHECK (status IN ('Pending', 'Under Review', 'Approved', 'Rejected', 'Ready', 'Completed', 'Cancelled')),
        document_number VARCHAR(50),
        approval_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Blotter Records table
    await client.query(`
      CREATE TABLE IF NOT EXISTS blotter_records (
        id SERIAL PRIMARY KEY,
        case_number VARCHAR(50) UNIQUE NOT NULL,
        complainant VARCHAR(150) NOT NULL,
        respondent VARCHAR(150) NOT NULL,
        incident_type VARCHAR(100) NOT NULL,
        incident_date DATE NOT NULL,
        incident_time TIME NOT NULL,
        location TEXT NOT NULL,
        description TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'Open' CHECK (status IN ('Open', 'Under Investigation', 'Resolved', 'Closed')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Announcements table
    await client.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Activity Logs table
    await client.query(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100),
        role VARCHAR(50),
        action TEXT NOT NULL,
        module VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // System Settings table
    await client.query(`
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT
      );
    `);

    // Insert Default System Settings
    await client.query(`
      INSERT INTO system_settings (setting_key, setting_value) VALUES 
      ('barangay_name', 'Barangay Central'),
      ('barangay_address', 'City Proper, Philippines'),
      ('contact_number', '09123456789'),
      ('email', 'contact@brgycentral.gov.ph')
      ON CONFLICT (setting_key) DO NOTHING;
    `);

    // Default Admin Account (admin / admin123)
    const adminCheck = await client.query("SELECT * FROM users WHERE role = 'admin' LIMIT 1");
    if (adminCheck.rows.length === 0) {
      const hashedPass = await bcrypt.hash('admin123', 10);
      await client.query(
        `INSERT INTO users (username, password, role, status, force_password_change) VALUES ($1, $2, $3, $4, $5)`,
        ['admin', hashedPass, 'admin', 'approved', true]
      );
      console.log('Default admin created: admin / admin123');
    }

    await client.query('COMMIT');
    console.log('Database tables verified/initialized successfully.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Database initialization failed:', err);
  } finally {
    client.release();
  }
}

// --- MIDDLEWARES ---
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login');
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.session && req.session.user && (req.session.user.role === role || req.session.user.role === 'admin')) {
      return next();
    }
    res.status(403).send('Access Denied.');
  };
}

async function logActivity(username, role, action, module) {
  try {
    await pool.query(
      `INSERT INTO activity_logs (username, role, action, module) VALUES ($1, $2, $3, $4)`,
      [username || 'System', role || 'System', action, module]
    );
  } catch (err) {
    console.error('Activity Logging Error:', err);
  }
}

// --- ROUTES: AUTHENTICATION ---
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.send(renderLayout('Login', `
    <div style="max-width: 400px; margin: 60px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
      <h2 style="text-align: center; margin-bottom: 20px; color: #1e3a8a;">Barangay System Login</h2>
      <form action="/login" method="POST">
        <div style="margin-bottom: 15px;">
          <label style="display: block; margin-bottom: 5px; font-weight: 600;">Username</label>
          <input type="text" name="username" required style="width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 4px;">
        </div>
        <div style="margin-bottom: 20px;">
          <label style="display: block; margin-bottom: 5px; font-weight: 600;">Password</label>
          <input type="password" name="password" required style="width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 4px;">
        </div>
        <button type="submit" style="width: 100%; padding: 12px; background: #2563eb; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Login</button>
      </form>
      <div style="text-align: center; margin-top: 15px;">
        <a href="/register" style="color: #2563eb; text-decoration: none;">Resident Account Registration</a>
      </div>
    </div>
  `));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.send(renderAlert('User not found.', '/login'));

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send(renderAlert('Invalid password.', '/login'));

    if (user.status === 'pending') return res.send(renderAlert('Account is pending admin approval.', '/login'));
    if (user.status !== 'approved') return res.send(renderAlert('Account is inactive or rejected.', '/login'));

    req.session.user = { id: user.id, username: user.username, role: user.role };
    await logActivity(user.username, user.role, 'User logged in', 'Authentication');

    if (user.force_password_change) return res.redirect('/change-password');

    if (user.role === 'admin') res.redirect('/admin');
    else if (user.role === 'staff') res.redirect('/staff');
    else res.redirect('/resident');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.get('/register', (req, res) => {
  res.send(renderLayout('Resident Registration', `
    <div style="max-width: 600px; margin: 30px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
      <h2 style="text-align: center; margin-bottom: 20px; color: #1e3a8a;">Resident Account Registration</h2>
      <form action="/register" method="POST">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
          <div style="grid-column: span 2;"><label>Full Name</label><input type="text" name="full_name" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Birthdate</label><input type="date" name="birthdate" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Sex</label><select name="sex" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>Male</option><option>Female</option></select></div>
          <div><label>Civil Status</label><select name="civil_status" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>Single</option><option>Married</option><option>Widowed</option><option>Separated</option></select></div>
          <div><label>Contact Number</label><input type="text" name="contact_number" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div style="grid-column: span 2;"><label>Complete Address</label><input type="text" name="address" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Username</label><input type="text" name="username" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Password</label><input type="password" name="password" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
        </div>
        <button type="submit" style="width: 100%; margin-top: 20px; padding: 12px; background: #16a34a; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Register</button>
      </form>
      <div style="text-align: center; margin-top: 15px;"><a href="/login" style="color: #2563eb; text-decoration: none;">Back to Login</a></div>
    </div>
  `));
});

app.post('/register', async (req, res) => {
  const { username, password, full_name, birthdate, sex, civil_status, address, contact_number } = req.body;
  try {
    const hashedPass = await bcrypt.hash(password, 10);
    const userResult = await pool.query(
      `INSERT INTO users (username, password, role, status) VALUES ($1, $2, 'resident', 'pending') RETURNING id`,
      [username, hashedPass]
    );
    const userId = userResult.rows[0].id;
    const residentId = `BRGY-${new Date().getFullYear()}-${Math.floor(100000 + Math.random() * 900000)}`;
    const qrImage = await QRCode.toDataURL(residentId);

    await pool.query(
      `INSERT INTO residents (user_id, resident_id, full_name, birthdate, sex, civil_status, address, contact_number, qr_code) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [userId, residentId, full_name, birthdate, sex, civil_status, address, contact_number, qrImage]
    );

    res.send(renderAlert('Registration successful! Await admin approval.', '/login'));
  } catch (err) {
    console.error(err);
    res.send(renderAlert('Registration failed. Username may already exist.', '/register'));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/change-password', isAuthenticated, (req, res) => {
  res.send(renderLayout('Change Password', `
    <div style="max-width: 400px; margin: 60px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
      <h2>Set New Password</h2>
      <form action="/change-password" method="POST">
        <div style="margin-bottom: 15px;"><label>New Password</label><input type="password" name="password" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
        <button type="submit" style="width:100%; padding:10px; background:#2563eb; color:white; border:none; border-radius:4px; font-weight:bold;">Update</button>
      </form>
    </div>
  `));
});

app.post('/change-password', isAuthenticated, async (req, res) => {
  const { password } = req.body;
  const hashedPass = await bcrypt.hash(password, 10);
  await pool.query('UPDATE users SET password = $1, force_password_change = FALSE WHERE id = $2', [hashedPass, req.session.user.id]);
  res.redirect('/login');
});

// --- ADMIN PORTAL ---
app.get('/admin', isAuthenticated, requireRole('admin'), async (req, res) => {
  const stats = await Promise.all([
    pool.query('SELECT COUNT(*) FROM residents WHERE is_archived = FALSE'),
    pool.query('SELECT COUNT(*) FROM households'),
    pool.query("SELECT COUNT(*) FROM users WHERE status = 'pending'"),
    pool.query("SELECT COUNT(*) FROM document_requests WHERE status = 'Pending'")
  ]);

  const counts = {
    residents: stats[0].rows[0].count,
    households: stats[1].rows[0].count,
    pendingUsers: stats[2].rows[0].count,
    pendingDocs: stats[3].rows[0].count
  };

  res.send(renderLayout('Admin Dashboard', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 25px; background: #f8fafc;">
        <h2>Admin Dashboard</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <div style="color: #64748b;">Total Residents</div>
            <div style="font-size: 24px; font-weight: bold; margin-top: 5px;">${counts.residents}</div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <div style="color: #64748b;">Households</div>
            <div style="font-size: 24px; font-weight: bold; margin-top: 5px;">${counts.households}</div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <div style="color: #64748b;">Pending Registrations</div>
            <div style="font-size: 24px; font-weight: bold; margin-top: 5px; color: #d97706;">${counts.pendingUsers}</div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <div style="color: #64748b;">Pending Documents</div>
            <div style="font-size: 24px; font-weight: bold; margin-top: 5px; color: #2563eb;">${counts.pendingDocs}</div>
          </div>
        </div>
      </div>
    </div>
  `));
});

app.get('/admin/residents', isAuthenticated, requireRole('admin'), async (req, res) => {
  const search = req.query.search || '';
  let query = 'SELECT * FROM residents WHERE is_archived = FALSE';
  let params = [];
  if (search) {
    query += ' AND (full_name ILIKE $1 OR resident_id ILIKE $1)';
    params.push(`%${search}%`);
  }
  const result = await pool.query(query, params);

  res.send(renderLayout('Resident Management', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 25px; background: #f8fafc;">
        <h2>Resident Management</h2>
        <form method="GET" style="margin: 20px 0;">
          <input type="text" name="search" value="${search}" placeholder="Search name or ID..." style="padding: 8px; width: 300px; border: 1px solid #ccc; border-radius: 4px;">
          <button type="submit" style="padding: 8px 15px; background: #2563eb; color: white; border: none; border-radius: 4px;">Search</button>
        </form>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">ID</th><th>Name</th><th>Sex</th><th>Contact</th><th>Address</th>
          </tr>
          ${result.rows.map(r => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${r.resident_id}</td>
              <td style="padding: 12px;">${r.full_name}</td>
              <td style="padding: 12px;">${r.sex}</td>
              <td style="padding: 12px;">${r.contact_number}</td>
              <td style="padding: 12px;">${r.address}</td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `));
});

app.get('/admin/users', isAuthenticated, requireRole('admin'), async (req, res) => {
  const users = await pool.query('SELECT * FROM users');
  res.send(renderLayout('User Accounts', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 25px; background: #f8fafc;">
        <h2>User Account Approvals</h2>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">Username</th><th>Role</th><th>Status</th><th>Action</th>
          </tr>
          ${users.rows.map(u => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${u.username}</td>
              <td style="padding: 12px;">${u.role}</td>
              <td style="padding: 12px;">${u.status}</td>
              <td style="padding: 12px;">
                ${u.status === 'pending' ? `<a href="/admin/users/approve/${u.id}" style="color: #16a34a; font-weight: bold;">Approve</a>` : ''}
              </td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `));
});

app.get('/admin/users/approve/:id', isAuthenticated, requireRole('admin'), async (req, res) => {
  await pool.query("UPDATE users SET status = 'approved' WHERE id = $1", [req.params.id]);
  res.redirect('/admin/users');
});

app.get('/admin/documents', isAuthenticated, requireRole('admin'), async (req, res) => {
  const docs = await pool.query(`
    SELECT d.*, r.full_name FROM document_requests d 
    JOIN residents r ON d.resident_id = r.id
  `);
  res.send(renderLayout('Document Requests', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 25px; background: #f8fafc;">
        <h2>Document Requests</h2>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">Request ID</th><th>Resident</th><th>Document</th><th>Status</th><th>Action</th>
          </tr>
          ${docs.rows.map(d => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${d.request_id}</td>
              <td style="padding: 12px;">${d.full_name}</td>
              <td style="padding: 12px;">${d.document_type}</td>
              <td style="padding: 12px;">${d.status}</td>
              <td style="padding: 12px;">
                <a href="/admin/documents/action/${d.id}/Approved" style="color: #16a34a; margin-right: 10px; font-weight: bold;">Approve</a>
                <a href="/admin/documents/print/${d.id}" target="_blank" style="color: #2563eb;">Print</a>
              </td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `));
});

app.get('/admin/documents/action/:id/:status', isAuthenticated, requireRole('admin'), async (req, res) => {
  const { id, status } = req.params;
  const docNum = `DOC-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
  await pool.query('UPDATE document_requests SET status = $1, document_number = $2, approval_date = CURRENT_TIMESTAMP WHERE id = $3', [status, docNum, id]);
  res.redirect('/admin/documents');
});

app.get('/admin/documents/print/:id', isAuthenticated, async (req, res) => {
  const doc = await pool.query(`
    SELECT d.*, r.full_name, r.address, r.resident_id FROM document_requests d 
    JOIN residents r ON d.resident_id = r.id WHERE d.id = $1
  `, [req.params.id]);
  if (doc.rows.length === 0) return res.status(404).send('Document not found');
  const d = doc.rows[0];

  res.send(`
    <html>
      <head><title>${d.document_type}</title></head>
      <body style="font-family: Arial, sans-serif; padding: 50px; max-width: 800px; margin: 0 auto; border: 2px solid #1e3a8a;">
        <div style="text-align: center;">
          <h3>REPUBLIC OF THE PHILIPPINES</h3>
          <h4>BARANGAY CENTRAL</h4>
          <h1 style="margin-top: 20px; color: #1e3a8a;">${d.document_type.toUpperCase()}</h1>
        </div>
        <p style="margin-top: 40px;">TO WHOM IT MAY CONCERN:</p>
        <p style="text-indent: 40px; line-height: 1.8;">This is to certify that <strong>${d.full_name}</strong>, of legal age, is a permanent resident of ${d.address}, and is a person of good moral character.</p>
        <p style="text-indent: 40px; line-height: 1.8;">This certification is issued upon the request for <strong>${d.purpose}</strong>.</p>
        <p style="margin-top: 40px;">Document No: <strong>${d.document_number || 'N/A'}</strong></p>
        <div style="float: right; margin-top: 80px; text-align: center;">
          <div style="border-bottom: 1px solid black; width: 200px; margin-bottom: 5px;"></div>
          <strong>PUNONG BARANGAY</strong>
        </div>
        <script>window.print();</script>
      </body>
    </html>
  `);
});

// --- STAFF PORTAL ---
app.get('/staff', isAuthenticated, requireRole('staff'), (req, res) => {
  res.send(renderLayout('Staff Portal', `
    <div style="display: flex;">
      ${renderSidebar('staff')}
      <div style="flex: 1; padding: 25px; background: #f8fafc;">
        <h2>Staff Portal Dashboard</h2>
        <p>Welcome to barangay staff management tools.</p>
      </div>
    </div>
  `));
});

// --- RESIDENT PORTAL ---
app.get('/resident', isAuthenticated, requireRole('resident'), async (req, res) => {
  const residentRes = await pool.query('SELECT * FROM residents WHERE user_id = $1', [req.session.user.id]);
  if (residentRes.rows.length === 0) return res.send('Resident profile not found.');
  const resident = residentRes.rows[0];

  const requests = await pool.query('SELECT * FROM document_requests WHERE resident_id = $1', [resident.id]);

  res.send(renderLayout('Resident Portal', `
    <div style="min-height: 100vh; background: #f8fafc;">
      <div style="background: #1e3a8a; color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center;">
        <h2>Resident Portal</h2>
        <div>
          <span style="margin-right: 15px;">${resident.full_name}</span>
          <a href="/logout" style="color: #fca5a5; text-decoration: underline;">Logout</a>
        </div>
      </div>
      <div style="padding: 30px; max-width: 900px; margin: 0 auto;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <h3>My Resident ID Card</h3>
            <p style="margin-top: 10px;"><strong>ID Number:</strong> ${resident.resident_id}</p>
            <div style="text-align: center; margin-top: 15px;">
              <img src="${resident.qr_code}" alt="QR Code" style="width: 140px; height: 140px;">
            </div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <h3>Request Document</h3>
            <form action="/resident/request" method="POST" style="margin-top: 10px;">
              <div style="margin-bottom: 10px;">
                <label>Document Type</label>
                <select name="document_type" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;">
                  <option>Barangay Clearance</option>
                  <option>Certificate of Residency</option>
                  <option>Certificate of Indigency</option>
                </select>
              </div>
              <div style="margin-bottom: 10px;">
                <label>Purpose</label>
                <input type="text" name="purpose" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;">
              </div>
              <button type="submit" style="width: 100%; padding: 10px; background: #2563eb; color: white; border: none; border-radius: 4px; font-weight: bold;">Submit</button>
            </form>
          </div>
        </div>
        <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
          <h3>Request History</h3>
          <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
            <tr style="background: #f1f5f9; text-align: left;"><th style="padding: 8px;">Request ID</th><th>Type</th><th>Purpose</th><th>Status</th></tr>
            ${requests.rows.map(req => `
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 8px;">${req.request_id}</td>
                <td style="padding: 8px;">${req.document_type}</td>
                <td style="padding: 8px;">${req.purpose}</td>
                <td style="padding: 8px;">${req.status}</td>
              </tr>
            `).join('')}
          </table>
        </div>
      </div>
    </div>
  `));
});

app.post('/resident/request', isAuthenticated, requireRole('resident'), async (req, res) => {
  const { document_type, purpose } = req.body;
  const residentRes = await pool.query('SELECT id FROM residents WHERE user_id = $1', [req.session.user.id]);
  if (residentRes.rows.length === 0) return res.send('Profile error.');
  const residentId = residentRes.rows[0].id;
  const requestId = `REQ-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;

  await pool.query('INSERT INTO document_requests (request_id, resident_id, document_type, purpose) VALUES ($1, $2, $3, $4)', [requestId, residentId, document_type, purpose]);
  res.redirect('/resident');
});

// --- UI LAYOUT UTILITIES ---
function renderLayout(title, content) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title}</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }
        body { background: #f1f5f9; color: #1e293b; }
        a { text-decoration: none; }
      </style>
    </head>
    <body>
      ${content}
    </body>
    </html>
  `;
}

function renderSidebar(role) {
  const links = role === 'admin' ? `
    <a href="/admin" style="color: white; display: block; padding: 10px 0;">Dashboard</a>
    <a href="/admin/residents" style="color: white; display: block; padding: 10px 0;">Residents</a>
    <a href="/admin/users" style="color: white; display: block; padding: 10px 0;">User Approvals</a>
    <a href="/admin/documents" style="color: white; display: block; padding: 10px 0;">Documents</a>
  ` : `
    <a href="/staff" style="color: white; display: block; padding: 10px 0;">Dashboard</a>
  `;

  return `
    <div style="width: 250px; background: #1e3a8a; color: white; min-height: 100vh; padding: 20px;">
      <h3 style="margin-bottom: 20px; border-bottom: 1px solid #3b82f6; padding-bottom: 10px;">Brgy Portal</h3>
      ${links}
      <hr style="border-color: #3b82f6; margin: 20px 0;">
      <a href="/logout" style="color: #fca5a5; display: block; padding: 10px 0;">Logout</a>
    </div>
  `;
}

function renderAlert(message, redirectUrl) {
  return `
    <script>
      alert("${message}");
      window.location.href = "${redirectUrl}";
    </script>
  `;
}

// --- SERVER INITIALIZATION ---
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server started and listening on port ${PORT}`);
  });
});
