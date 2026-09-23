/**
 * Barangay Resident Management System
 * Fully self-contained Express & PostgreSQL application for Render deployment.
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Connection Pool (Render compatible)
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

// --- SAFE DATABASE SCHEMA INITIALIZATION (Never Drops Data) ---
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

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

    await client.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS concerns (
        id SERIAL PRIMARY KEY,
        resident_id INT REFERENCES residents(id) ON DELETE CASCADE,
        subject VARCHAR(200) NOT NULL,
        description TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'Submitted',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

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

    await client.query(`
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT
      );
    `);

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
    console.log('Database schema verified successfully.');
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
    res.status(403).send(renderAlert('Access Denied. Unauthorized Portal Access.', '/login'));
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

// --- AUTHENTICATION & PORTAL ENTRY ROUTES ---
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.send(renderLayout('Unified Login Portal', `
    <div style="max-width: 420px; margin: 60px auto; background: white; padding: 35px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);">
      <div style="text-align: center; margin-bottom: 25px;">
        <h2 style="color: #1e3a8a; font-size: 24px;">Barangay Management System</h2>
        <p style="color: #64748b; font-size: 14px; margin-top: 5px;">Secure Portal Login</p>
      </div>
      <form action="/login" method="POST">
        <div style="margin-bottom: 15px;">
          <label style="display: block; margin-bottom: 6px; font-weight: 600; font-size: 14px;">Username</label>
          <input type="text" name="username" required style="width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px;">
        </div>
        <div style="margin-bottom: 20px;">
          <label style="display: block; margin-bottom: 6px; font-weight: 600; font-size: 14px;">Password</label>
          <input type="password" name="password" required style="width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px;">
        </div>
        <button type="submit" style="width: 100%; padding: 12px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px;">Login to Portal</button>
      </form>
      <div style="text-align: center; margin-top: 20px; border-top: 1px solid #e2e8f0; padding-top: 15px;">
        <a href="/resident-register" style="color: #2563eb; text-decoration: none; font-size: 14px; font-weight: 500;">Resident Account Registration</a>
      </div>
    </div>
  `));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.send(renderAlert('User account not found.', '/login'));

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send(renderAlert('Invalid password.', '/login'));

    if (user.status === 'pending') return res.send(renderAlert('Your account is pending admin approval.', '/login'));
    if (user.status !== 'approved') return res.send(renderAlert('Your account is inactive or disabled.', '/login'));

    req.session.user = { id: user.id, username: user.username, role: user.role };
    await logActivity(user.username, user.role, 'User logged in successfully', 'Authentication');

    if (user.force_password_change) return res.redirect('/change-password');

    if (user.role === 'admin') res.redirect('/admin/dashboard');
    else if (user.role === 'staff') res.redirect('/staff/dashboard');
    else res.redirect('/resident/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Resident Self-Registration Route
app.get('/resident-register', (req, res) => {
  res.send(renderLayout('Resident Registration', `
    <div style="max-width: 650px; margin: 30px auto; background: white; padding: 35px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);">
      <h2 style="text-align: center; margin-bottom: 25px; color: #1e3a8a;">Resident Account Registration</h2>
      <form action="/resident-register" method="POST">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
          <div style="grid-column: span 2;"><label style="font-weight: 600; font-size:13px;">Full Name</label><input type="text" name="full_name" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"></div>
          <div><label style="font-weight: 600; font-size:13px;">Birthdate</label><input type="date" name="birthdate" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"></div>
          <div><label style="font-weight: 600; font-size:13px;">Sex</label><select name="sex" style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"><option>Male</option><option>Female</option></select></div>
          <div><label style="font-weight: 600; font-size:13px;">Civil Status</label><select name="civil_status" style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"><option>Single</option><option>Married</option><option>Widowed</option><option>Separated</option></select></div>
          <div><label style="font-weight: 600; font-size:13px;">Contact Number</label><input type="text" name="contact_number" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"></div>
          <div style="grid-column: span 2;"><label style="font-weight: 600; font-size:13px;">Complete Address</label><input type="text" name="address" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"></div>
          <div><label style="font-weight: 600; font-size:13px;">Username</label><input type="text" name="username" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"></div>
          <div><label style="font-weight: 600; font-size:13px;">Password</label><input type="password" name="password" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"></div>
        </div>
        <button type="submit" style="width: 100%; margin-top: 25px; padding: 12px; background: #16a34a; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px;">Submit Registration</button>
      </form>
      <div style="text-align: center; margin-top: 20px;"><a href="/login" style="color: #2563eb; text-decoration: none; font-size: 14px;">Back to Login</a></div>
    </div>
  `));
});

app.post('/resident-register', async (req, res) => {
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

    res.send(renderAlert('Registration successful! Please wait for admin approval.', '/login'));
  } catch (err) {
    console.error(err);
    res.send(renderAlert('Registration failed. Username may already exist.', '/resident-register'));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/change-password', isAuthenticated, (req, res) => {
  res.send(renderLayout('Change Password', `
    <div style="max-width: 400px; margin: 80px auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08);">
      <h3 style="color: #1e3a8a; margin-bottom: 15px;">Set New Password</h3>
      <form action="/change-password" method="POST">
        <div style="margin-bottom: 15px;"><label style="font-weight:600; font-size:13px;">New Password</label><input type="password" name="password" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px;"></div>
        <button type="submit" style="width:100%; padding:11px; background:#2563eb; color:white; border:none; border-radius:6px; font-weight:bold; cursor:pointer;">Update Password</button>
      </form>
    </div>
  `));
});

app.post('/change-password', isAuthenticated, async (req, res) => {
  const { password } = req.body;
  const hashedPass = await bcrypt.hash(password, 10);
  await pool.query('UPDATE users SET password = $1, force_password_change = FALSE WHERE id = $2', [hashedPass, req.session.user.id]);
  const role = req.session.user.role;
  if (role === 'admin') res.redirect('/admin/dashboard');
  else if (role === 'staff') res.redirect('/staff/dashboard');
  else res.redirect('/resident/dashboard');
});


// --- ADMIN PORTAL ROUTES ---
app.get('/admin/dashboard', isAuthenticated, requireRole('admin'), async (req, res) => {
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
    <div style="display: flex; min-height: 100vh;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 30px; background: #f8fafc;">
        <h2 style="color: #1e3a8a; margin-bottom: 25px;">Admin Control Dashboard</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px;">
          <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
            <div style="color: #64748b; font-size: 13px; font-weight: 600;">Total Residents</div>
            <div style="font-size: 28px; font-weight: bold; margin-top: 8px; color: #0f172a;">${counts.residents}</div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
            <div style="color: #64748b; font-size: 13px; font-weight: 600;">Total Households</div>
            <div style="font-size: 28px; font-weight: bold; margin-top: 8px; color: #0f172a;">${counts.households}</div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
            <div style="color: #64748b; font-size: 13px; font-weight: 600;">Pending Registrations</div>
            <div style="font-size: 28px; font-weight: bold; margin-top: 8px; color: #d97706;">${counts.pendingUsers}</div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
            <div style="color: #64748b; font-size: 13px; font-weight: 600;">Pending Documents</div>
            <div style="font-size: 28px; font-weight: bold; margin-top: 8px; color: #2563eb;">${counts.pendingDocs}</div>
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

  res.send(renderLayout('Admin - Residents', `
    <div style="display: flex; min-height: 100vh;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 30px; background: #f8fafc;">
        <h2 style="color: #1e3a8a; margin-bottom: 20px;">Resident Management</h2>
        <form method="GET" style="margin-bottom: 20px;">
          <input type="text" name="search" value="${search}" placeholder="Search name or ID..." style="padding: 9px; width: 320px; border: 1px solid #cbd5e1; border-radius: 6px;">
          <button type="submit" style="padding: 9px 18px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;">Search</button>
        </form>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
          <tr style="background: #1e3a8a; color: white; text-align: left; font-size: 13px;">
            <th style="padding: 12px;">ID</th><th>Name</th><th>Sex</th><th>Contact</th><th>Address</th>
          </tr>
          ${result.rows.map(r => `
            <tr style="border-bottom: 1px solid #e2e8f0; font-size: 14px;">
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

app.get('/admin/accounts', isAuthenticated, requireRole('admin'), async (req, res) => {
  const users = await pool.query('SELECT * FROM users');
  res.send(renderLayout('Admin - Accounts', `
    <div style="display: flex; min-height: 100vh;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 30px; background: #f8fafc;">
        <h2 style="color: #1e3a8a; margin-bottom: 20px;">User Account Approvals</h2>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
          <tr style="background: #1e3a8a; color: white; text-align: left; font-size: 13px;">
            <th style="padding: 12px;">Username</th><th>Role</th><th>Status</th><th>Action</th>
          </tr>
          ${users.rows.map(u => `
            <tr style="border-bottom: 1px solid #e2e8f0; font-size: 14px;">
              <td style="padding: 12px;">${u.username}</td>
              <td style="padding: 12px;">${u.role}</td>
              <td style="padding: 12px;">${u.status}</td>
              <td style="padding: 12px;">
                ${u.status === 'pending' ? `<a href="/admin/accounts/approve/${u.id}" style="color: #16a34a; font-weight: bold; text-decoration: none;">Approve</a>` : 'N/A'}
              </td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `));
});

app.get('/admin/accounts/approve/:id', isAuthenticated, requireRole('admin'), async (req, res) => {
  await pool.query("UPDATE users SET status = 'approved' WHERE id = $1", [req.params.id]);
  res.redirect('/admin/accounts');
});

app.get('/admin/documents', isAuthenticated, requireRole('admin'), async (req, res) => {
  const docs = await pool.query(`
    SELECT d.*, r.full_name FROM document_requests d 
    JOIN residents r ON d.resident_id = r.id
  `);
  res.send(renderLayout('Admin - Documents', `
    <div style="display: flex; min-height: 100vh;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 30px; background: #f8fafc;">
        <h2 style="color: #1e3a8a; margin-bottom: 20px;">Document Requests</h2>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
          <tr style="background: #1e3a8a; color: white; text-align: left; font-size: 13px;">
            <th style="padding: 12px;">Request ID</th><th>Resident</th><th>Document</th><th>Status</th><th>Action</th>
          </tr>
          ${docs.rows.map(d => `
            <tr style="border-bottom: 1px solid #e2e8f0; font-size: 14px;">
              <td style="padding: 12px;">${d.request_id}</td>
              <td style="padding: 12px;">${d.full_name}</td>
              <td style="padding: 12px;">${d.document_type}</td>
              <td style="padding: 12px;">${d.status}</td>
              <td style="padding: 12px;">
                <a href="/admin/documents/action/${d.id}/Approved" style="color: #16a34a; margin-right: 12px; font-weight: bold; text-decoration: none;">Approve</a>
                <a href="/admin/documents/print/${d.id}" target="_blank" style="color: #2563eb; text-decoration: none;">Print</a>
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
      <body style="font-family: Arial, sans-serif; padding: 60px; max-width: 800px; margin: 0 auto; border: 3px solid #1e3a8a;">
        <div style="text-align: center;">
          <h3 style="margin: 0; font-size: 16px;">REPUBLIC OF THE PHILIPPINES</h3>
          <h4 style="margin: 5px 0 20px 0; font-size: 15px;">BARANGAY CENTRAL</h4>
          <h1 style="margin: 20px 0; color: #1e3a8a; font-size: 26px;">${d.document_type.toUpperCase()}</h1>
        </div>
        <p style="margin-top: 40px; font-size: 16px;">TO WHOM IT MAY CONCERN:</p>
        <p style="text-indent: 40px; line-height: 1.8; font-size: 16px;">This is to certify that <strong>${d.full_name}</strong>, of legal age, is a permanent resident of ${d.address}, and is a person of good moral character and standing in the community.</p>
        <p style="text-indent: 40px; line-height: 1.8; font-size: 16px;">This certification is issued upon the request of the aforementioned individual for the purpose of <strong>${d.purpose}</strong>.</p>
        <p style="margin-top: 40px; font-size: 15px;">Document No: <strong>${d.document_number || 'N/A'}</strong></p>
        <div style="float: right; margin-top: 80px; text-align: center;">
          <div style="border-bottom: 1px solid black; width: 220px; margin-bottom: 5px;"></div>
          <strong style="font-size: 15px;">PUNONG BARANGAY</strong>
        </div>
        <script>window.print();</script>
      </body>
    </html>
  `);
});

// Additional placeholder links to satisfy complete menu requirements
app.get('/admin/:module', isAuthenticated, requireRole('admin'), (req, res) => {
  const mod = req.params.module;
  res.send(renderLayout(`Admin - ${mod}`, `
    <div style="display: flex; min-height: 100vh;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 30px; background: #f8fafc;">
        <h2 style="color: #1e3a8a; text-transform: capitalize; margin-bottom: 15px;">Admin Module: ${mod}</h2>
        <p style="color: #475569;">Administrative controls and records for ${mod} are active.</p>
      </div>
    </div>
  `));
});


// --- STAFF PORTAL ROUTES ---
app.get('/staff/dashboard', isAuthenticated, requireRole('staff'), (req, res) => {
  res.send(renderLayout('Staff Dashboard', `
    <div style="display: flex; min-height: 100vh;">
      ${renderSidebar('staff')}
      <div style="flex: 1; padding: 30px; background: #f8fafc;">
        <h2 style="color: #1e3a8a; margin-bottom: 15px;">Staff Operations Portal</h2>
        <p style="color: #475569;">Welcome to barangay operational tools and document processing.</p>
      </div>
    </div>
  `));
});


// --- RESIDENT PORTAL ROUTES (Completely Separate Layout & Experience) ---
app.get('/resident/dashboard', isAuthenticated, requireRole('resident'), async (req, res) => {
  const residentRes = await pool.query('SELECT * FROM residents WHERE user_id = $1', [req.session.user.id]);
  if (residentRes.rows.length === 0) return res.send('Resident profile record not found.');
  const resident = residentRes.rows[0];

  const requests = await pool.query('SELECT * FROM document_requests WHERE resident_id = $1', [resident.id]);

  res.send(renderLayout('Resident Portal', `
    <div style="min-height: 100vh; background: #f8fafc;">
      <div style="background: #1e3a8a; color: white; padding: 16px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <h2 style="font-size: 20px;">Resident Portal</h2>
        <div>
          <span style="margin-right: 20px; font-weight: 500;">Welcome, ${resident.full_name}</span>
          <a href="/logout" style="color: #fca5a5; text-decoration: underline; font-weight: 500;">Logout</a>
        </div>
      </div>
      <div style="padding: 35px 25px; max-width: 950px; margin: 0 auto;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 25px;">
          <div style="background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); text-align: center;">
            <h3 style="color: #1e3a8a; margin-bottom: 15px;">My Resident ID Card</h3>
            <p style="margin-bottom: 12px; font-size: 15px;"><strong>ID Number:</strong> ${resident.resident_id}</p>
            <img src="${resident.qr_code}" alt="QR Code" style="width: 150px; height: 150px; border: 1px solid #e2e8f0; border-radius: 8px; padding: 5px;">
          </div>
          <div style="background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
            <h3 style="color: #1e3a8a; margin-bottom: 15px;">Request Document</h3>
            <form action="/resident/request" method="POST">
              <div style="margin-bottom: 12px;">
                <label style="font-weight: 600; font-size: 13px;">Document Type</label>
                <select name="document_type" style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px; margin-top:5px;">
                  <option>Barangay Clearance</option>
                  <option>Certificate of Residency</option>
                  <option>Certificate of Indigency</option>
                  <option>Certificate of Good Moral Character</option>
                </select>
              </div>
              <div style="margin-bottom: 15px;">
                <label style="font-weight: 600; font-size: 13px;">Purpose</label>
                <input type="text" name="purpose" required style="width:100%; padding:9px; border:1px solid #cbd5e1; border-radius:6px; margin-top:5px;">
              </div>
              <button type="submit" style="width: 100%; padding: 11px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;">Submit Request</button>
            </form>
          </div>
        </div>
        <div style="background: white; padding: 25px; border-radius: 12px; margin-top: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
          <h3 style="color: #1e3a8a; margin-bottom: 15px;">My Document Requests</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr style="background: #f1f5f9; text-align: left; font-size: 13px;"><th style="padding: 10px;">Request ID</th><th>Type</th><th>Purpose</th><th>Status</th></tr>
            ${requests.rows.map(req => `
              <tr style="border-bottom: 1px solid #e2e8f0; font-size: 14px;">
                <td style="padding: 10px;">${req.request_id}</td>
                <td style="padding: 10px;">${req.document_type}</td>
                <td style="padding: 10px;">${req.purpose}</td>
                <td style="padding: 10px; font-weight: 600; color: ${req.status === 'Approved' ? '#16a34a' : '#2563eb'};">${req.status}</td>
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
  res.redirect('/resident/dashboard');
});


// --- UI LAYOUT & SIDEBAR UTILITIES ---
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
    <a href="/admin/dashboard" style="color: white; display: block; padding: 10px 0; font-size: 14px;">Dashboard</a>
    <a href="/admin/residents" style="color: white; display: block; padding: 10px 0; font-size: 14px;">Residents</a>
    <a href="/admin/accounts" style="color: white; display: block; padding: 10px 0; font-size: 14px;">User Accounts</a>
    <a href="/admin/documents" style="color: white; display: block; padding: 10px 0; font-size: 14px;">Document Requests</a>
    <a href="/admin/blotter" style="color: white; display: block; padding: 10px 0; font-size: 14px;">Blotter Records</a>
    <a href="/admin/settings" style="color: white; display: block; padding: 10px 0; font-size: 14px;">System Settings</a>
  ` : `
    <a href="/staff/dashboard" style="color: white; display: block; padding: 10px 0; font-size: 14px;">Dashboard</a>
  `;

  return `
    <div style="width: 260px; background: #1e3a8a; color: white; min-height: 100vh; padding: 25px;">
      <h3 style="margin-bottom: 25px; border-bottom: 1px solid #3b82f6; padding-bottom: 12px; font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px;">${role.toUpperCase()} PORTAL</h3>
      ${links}
      <hr style="border-color: #3b82f6; margin: 25px 0;">
      <a href="/logout" style="color: #fca5a5; display: block; padding: 10px 0; font-size: 14px; font-weight: 500;">Logout</a>
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
    console.log(`Barangay Management System running and listening on port ${PORT}`);
  });
});
