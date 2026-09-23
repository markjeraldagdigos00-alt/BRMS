/**
 * Barangay Resident Management System
 * Single-file Node.js, Express, PostgreSQL application designed for Render.
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const QRCode = require('qrcode');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Connection Pool using DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'brgy-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

// --- DATABASE INITIALIZATION & SAFE SCHEMA MIGRATION ---
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Users Table (Admin, Staff, Resident)
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

    // 2. Residents Profile Table
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
        valid_id_path TEXT,
        resident_photo TEXT,
        qr_code TEXT,
        is_archived BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 3. Households Table
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

    // 4. Household Members Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS household_members (
        id SERIAL PRIMARY KEY,
        household_id INT REFERENCES households(id) ON DELETE CASCADE,
        resident_id INT REFERENCES residents(id) ON DELETE CASCADE,
        relationship VARCHAR(50) NOT NULL,
        UNIQUE(household_id, resident_id)
      );
    `);

    // 5. Staff Permissions Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS staff_permissions (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        module_name VARCHAR(100) NOT NULL,
        can_access BOOLEAN DEFAULT TRUE
      );
    `);

    // 6. Officials Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS officials (
        id SERIAL PRIMARY KEY,
        name VARCHAR(150) NOT NULL,
        position VARCHAR(100) NOT NULL,
        contact VARCHAR(30),
        term_start DATE,
        term_end DATE,
        status VARCHAR(20) DEFAULT 'Active',
        photo TEXT,
        signature TEXT
      );
    `);

    // 7. Document Requests Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS document_requests (
        id SERIAL PRIMARY KEY,
        request_id VARCHAR(50) UNIQUE NOT NULL,
        resident_id INT REFERENCES residents(id) ON DELETE CASCADE,
        document_type VARCHAR(100) NOT NULL,
        purpose TEXT NOT NULL,
        requirements_path TEXT,
        status VARCHAR(50) DEFAULT 'Pending' CHECK (status IN ('Pending', 'Under Review', 'Approved', 'Rejected', 'Ready', 'Completed', 'Cancelled')),
        remarks TEXT,
        processing_staff INT REFERENCES users(id) ON DELETE SET NULL,
        approval_date TIMESTAMP,
        completion_date TIMESTAMP,
        document_number VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 8. Blotter Records Table
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
        witnesses TEXT,
        action_taken TEXT,
        resolution TEXT,
        status VARCHAR(50) DEFAULT 'Open' CHECK (status IN ('Open', 'Under Investigation', 'Resolved', 'Closed')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 9. Announcements Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        content TEXT NOT NULL,
        image_url TEXT,
        is_published BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 10. Notifications Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 11. Activity Logs Table
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

    // 12. System Settings Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT
      );
    `);

    // Insert Default System Settings if missing
    await client.query(`
      INSERT INTO system_settings (setting_key, setting_value) VALUES 
      ('barangay_name', 'Barangay Central'),
      ('barangay_address', 'City Proper, Philippines'),
      ('contact_number', '09123456789'),
      ('email', 'contact@brgycentral.gov.ph'),
      ('system_title', 'Barangay Resident Management System')
      ON CONFLICT (setting_key) DO NOTHING;
    `);

    // Default Admin Account Creation (Only if no admin exists)
    const adminCheck = await client.query("SELECT * FROM users WHERE role = 'admin' LIMIT 1");
    if (adminCheck.rows.length === 0) {
      const hashedPass = await bcrypt.hash('admin123', 10);
      await client.query(
        `INSERT INTO users (username, password, role, status, force_password_change) VALUES ($1, $2, $3, $4, $5)`,
        ['admin', hashedPass, 'admin', 'approved', true]
      );
      console.log('Default admin account created: admin / admin123');
    }

    await client.query('COMMIT');
    console.log('Database initialized successfully.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

// --- MIDDLEWARES ---
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.redirect('/login');
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.session && req.session.user && (req.session.user.role === role || req.session.user.role === 'admin')) {
      return next();
    }
    res.status(403).send('Access Denied: You do not have permission to access this resource.');
  };
}

async function logActivity(username, role, action, module) {
  try {
    await pool.query(
      `INSERT INTO activity_logs (username, role, action, module) VALUES ($1, $2, $3, $4)`,
      [username || 'System', role || 'System', action, module]
    );
  } catch (err) {
    console.error('Logging Error:', err);
  }
}

// --- AUTHENTICATION ROUTES ---
app.get('/login', (req, res) => {
  res.send(renderLayout('Login', `
    <div style="max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
      <h2 style="text-align: center; margin-bottom: 20px; color: #1e3a8a;">Barangay Portal Login</h2>
      <form action="/login" method="POST">
        <div style="margin-bottom: 15px;">
          <label style="display: block; margin-bottom: 5px; font-weight: 600;">Username / Email</label>
          <input type="text" name="username" required style="width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 4px;">
        </div>
        <div style="margin-bottom: 20px;">
          <label style="display: block; margin-bottom: 5px; font-weight: 600;">Password</label>
          <input type="password" name="password" required style="width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 4px;">
        </div>
        <button type="submit" style="width: 100%; padding: 12px; background: #2563eb; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Login</button>
      </form>
      <div style="text-align: center; margin-top: 15px;">
        <a href="/register" style="color: #2563eb; text-decoration: none;">Resident Registration</a>
      </div>
    </div>
  `, req.session));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.send(renderAlert('User not found.', '/login'));

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send(renderAlert('Invalid password.', '/login'));

    if (user.status === 'pending') return res.send(renderAlert('Your account is pending administrator approval.', '/login'));
    if (user.status === 'rejected' || user.status === 'disabled') return res.send(renderAlert('Your account has been deactivated or rejected.', '/login'));

    req.session.user = { id: user.id, username: user.username, role: user.role };
    await logActivity(user.username, user.role, 'User logged in', 'Authentication');

    if (user.force_password_change) {
      return res.redirect('/change-password');
    }

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
          <div><label>Full Name</label><input type="text" name="full_name" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Birthdate</label><input type="date" name="birthdate" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Sex</label><select name="sex" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>Male</option><option>Female</option></select></div>
          <div><label>Civil Status</label><select name="civil_status" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>Single</option><option>Married</option><option>Widowed</option><option>Separated</option></select></div>
          <div style="grid-column: span 2;"><label>Complete Address</label><input type="text" name="address" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Contact Number</label><input type="text" name="contact_number" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Email</label><input type="email" name="email" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Occupation</label><input type="text" name="occupation" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Educational Attainment</label><input type="text" name="educational_attainment" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Voter Status</label><select name="voter_status" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>Yes</option><option>No</option></select></div>
          <div><label>PWD Status</label><select name="pwd_status" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>No</option><option>Yes</option></select></div>
          <div><label>Senior Citizen Status</label><select name="senior_citizen_status" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>No</option><option>Yes</option></select></div>
          <div><label>4Ps Status</label><select name="four_ps_status" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"><option>No</option><option>Yes</option></select></div>
          <div style="grid-column: span 2;"><label>Emergency Contact</label><input type="text" name="emergency_contact" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Username</label><input type="text" name="username" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
          <div><label>Password</label><input type="password" name="password" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
        </div>
        <button type="submit" style="width: 100%; margin-top: 20px; padding: 12px; background: #16a34a; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Register Account</button>
      </form>
      <div style="text-align: center; margin-top: 15px;"><a href="/login" style="color: #2563eb; text-decoration: none;">Already have an account? Login</a></div>
    </div>
  `, req.session));
});

app.post('/register', async (req, res) => {
  const { username, password, full_name, birthdate, sex, civil_status, address, contact_number, email, occupation, educational_attainment, voter_status, pwd_status, senior_citizen_status, four_ps_status, emergency_contact } = req.body;
  try {
    const hashedPass = await bcrypt.hash(password, 10);
    const userResult = await pool.query(
      `INSERT INTO users (username, password, role, status) VALUES ($1, $2, 'resident', 'pending') RETURNING id`,
      [username, hashedPass]
    );
    const userId = userResult.rows[0].id;

    const residentId = `BRGY-${new Date().getFullYear()}-${Math.floor(100000 + Math.random() * 900000)}`;
    const qrData = crypto.randomBytes(16).toString('hex');
    const qrImage = await QRCode.toDataURL(qrData);

    await pool.query(
      `INSERT INTO residents (user_id, resident_id, full_name, birthdate, sex, civil_status, address, contact_number, email, occupation, educational_attainment, voter_status, pwd_status, senior_citizen_status, four_ps_status, emergency_contact, qr_code) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
      [userId, residentId, full_name, birthdate, sex, civil_status, address, contact_number, email, occupation, educational_attainment, voter_status, pwd_status, senior_citizen_status, four_ps_status, emergency_contact, qrImage]
    );

    await logActivity(username, 'resident', 'Resident registered account', 'Authentication');
    res.send(renderAlert('Registration successful! Please wait for admin/staff approval.', '/login'));
  } catch (err) {
    console.error(err);
    res.send(renderAlert('Error during registration. Username or details might already exist.', '/register'));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/change-password', isAuthenticated, (req, res) => {
  res.send(renderLayout('Change Password', `
    <div style="max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
      <h2>Change Password Required</h2>
      <form action="/change-password" method="POST">
        <div style="margin-bottom: 15px;"><label>New Password</label><input type="password" name="password" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;"></div>
        <button type="submit" style="width:100%; padding:10px; background:#2563eb; color:white; border:none; border-radius:4px; font-weight:bold;">Update Password</button>
      </form>
    </div>
  `, req.session));
});

app.post('/change-password', isAuthenticated, async (req, res) => {
  const { password } = req.body;
  const hashedPass = await bcrypt.hash(password, 10);
  await pool.query('UPDATE users SET password = $1, force_password_change = FALSE WHERE id = $2', [hashedPass, req.session.user.id]);
  res.redirect('/login');
});

// --- ADMIN PORTAL ---
app.get('/admin', isAuthenticated, requireRole('admin'), async (req, res) => {
  const statsQuery = await Promise.all([
    pool.query('SELECT COUNT(*) FROM residents WHERE is_archived = FALSE'),
    pool.query('SELECT COUNT(*) FROM households'),
    pool.query("SELECT COUNT(*) FROM residents WHERE sex = 'Male' AND is_archived = FALSE"),
    pool.query("SELECT COUNT(*) FROM residents WHERE sex = 'Female' AND is_archived = FALSE"),
    pool.query("SELECT COUNT(*) FROM residents WHERE EXTRACT(YEAR FROM AGE(birthdate)) < 18 AND is_archived = FALSE"),
    pool.query("SELECT COUNT(*) FROM residents WHERE senior_citizen_status = 'Yes' AND is_archived = FALSE"),
    pool.query("SELECT COUNT(*) FROM residents WHERE pwd_status = 'Yes' AND is_archived = FALSE"),
    pool.query("SELECT COUNT(*) FROM residents WHERE voter_status = 'Yes' AND is_archived = FALSE"),
    pool.query("SELECT COUNT(*) FROM residents WHERE four_ps_status = 'Yes' AND is_archived = FALSE"),
    pool.query("SELECT COUNT(*) FROM users WHERE status = 'pending'"),
    pool.query("SELECT COUNT(*) FROM document_requests WHERE status = 'Pending'"),
    pool.query("SELECT COUNT(*) FROM document_requests WHERE status = 'Completed'"),
    pool.query("SELECT COUNT(*) FROM blotter_records WHERE status = 'Open'"),
    pool.query("SELECT COUNT(*) FROM blotter_records WHERE status = 'Resolved'")
  ]);

  const stats = {
    totalResidents: statsQuery[0].rows[0].count,
    totalHouseholds: statsQuery[1].rows[0].count,
    male: statsQuery[2].rows[0].count,
    female: statsQuery[3].rows[0].count,
    minors: statsQuery[4].rows[0].count,
    seniors: statsQuery[5].rows[0].count,
    pwd: statsQuery[6].rows[0].count,
    voters: statsQuery[7].rows[0].count,
    fourPs: statsQuery[8].rows[0].count,
    pendingReg: statsQuery[9].rows[0].count,
    pendingDocs: statsQuery[10].rows[0].count,
    completedDocs: statsQuery[11].rows[0].count,
    openBlotter: statsQuery[12].rows[0].count,
    resolvedBlotter: statsQuery[13].rows[0].count
  };

  res.send(renderLayout('Admin Dashboard', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Admin Dashboard</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
          ${Object.entries(stats).map(([k, v]) => `
            <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid #2563eb;">
              <div style="font-size: 14px; color: #64748b; text-transform: uppercase;">${k.replace(/([A-Z])/g, ' $1')}</div>
              <div style="font-size: 24px; font-weight: bold; margin-top: 5px; color: #1e293b;">${v}</div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `, req.session));
});

// Admin Residents Management
app.get('/admin/residents', isAuthenticated, requireRole('admin'), async (req, res) => {
  const { search = '', filter = '' } = req.query;
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
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Resident Management</h2>
        <form method="GET" style="margin: 20px 0;">
          <input type="text" name="search" value="${search}" placeholder="Search name or ID..." style="padding: 8px; width: 300px; border: 1px solid #ccc; border-radius: 4px;">
          <button type="submit" style="padding: 8px 15px; background: #2563eb; color: white; border: none; border-radius: 4px;">Search</button>
        </form>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">ID</th><th>Name</th><th>Birthdate</th><th>Sex</th><th>Contact</th><th>Actions</th>
          </tr>
          ${result.rows.map(r => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${r.resident_id}</td>
              <td style="padding: 12px;">${r.full_name}</td>
              <td style="padding: 12px;">${r.birthdate.toISOString().split('T')[0]}</td>
              <td style="padding: 12px;">${r.sex}</td>
              <td style="padding: 12px;">${r.contact_number}</td>
              <td style="padding: 12px;"><a href="/admin/residents/edit/${r.id}" style="color: #2563eb;">Edit</a></td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `, req.session));
});

// Household Management
app.get('/admin/households', isAuthenticated, requireRole('admin'), async (req, res) => {
  const households = await pool.query(`
    SELECT h.*, r.full_name as head_name FROM households h 
    LEFT JOIN residents r ON h.household_head_id = r.id
  `);
  res.send(renderLayout('Household Management', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Household Management</h2>
        <form action="/admin/households" method="POST" style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
          <h3>Add Household</h3>
          <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-top: 10px;">
            <input type="text" name="household_number" placeholder="Household Number" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <input type="text" name="address" placeholder="Address" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <button type="submit" style="background: #16a34a; color: white; border: none; border-radius: 4px; font-weight: bold;">Add Household</button>
          </div>
        </form>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px;">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">Household #</th><th>Address</th><th>Classification</th>
          </tr>
          ${households.rows.map(h => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${h.household_number}</td>
              <td style="padding: 12px;">${h.address}</td>
              <td style="padding: 12px;">${h.classification}</td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `, req.session));
});

app.post('/admin/households', isAuthenticated, requireRole('admin'), async (req, res) => {
  const { household_number, address } = req.body;
  await pool.query('INSERT INTO households (household_number, address) VALUES ($1, $2)', [household_number, address]);
  res.redirect('/admin/households');
});

// Admin User Approvals & Management
app.get('/admin/users', isAuthenticated, requireRole('admin'), async (req, res) => {
  const users = await pool.query('SELECT * FROM users');
  res.send(renderLayout('User Accounts', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>User Account Management</h2>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; margin-top: 20px;">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">Username</th><th>Role</th><th>Status</th><th>Actions</th>
          </tr>
          ${users.rows.map(u => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${u.username}</td>
              <td style="padding: 12px;">${u.role}</td>
              <td style="padding: 12px;">${u.status}</td>
              <td style="padding: 12px;">
                ${u.status === 'pending' ? `<a href="/admin/users/approve/${u.id}" style="color: #16a34a; margin-right: 10px;">Approve</a>` : ''}
                <a href="/admin/users/toggle/${u.id}" style="color: #dc2626;">Toggle Status</a>
              </td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `, req.session));
});

app.get('/admin/users/approve/:id', isAuthenticated, requireRole('admin'), async (req, res) => {
  await pool.query("UPDATE users SET status = 'approved' WHERE id = $1", [req.params.id]);
  res.redirect('/admin/users');
});

app.get('/admin/users/toggle/:id', isAuthenticated, requireRole('admin'), async (req, res) => {
  const user = await pool.query('SELECT status FROM users WHERE id = $1', [req.params.id]);
  const newStatus = user.rows[0].status === 'approved' ? 'disabled' : 'approved';
  await pool.query('UPDATE users SET status = $1 WHERE id = $2', [newStatus, req.params.id]);
  res.redirect('/admin/users');
});

// Document Requests Admin Review
app.get('/admin/documents', isAuthenticated, requireRole('admin'), async (req, res) => {
  const docs = await pool.query(`
    SELECT d.*, r.full_name FROM document_requests d 
    JOIN residents r ON d.resident_id = r.id
  `);
  res.send(renderLayout('Document Requests', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Document Requests Management</h2>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; margin-top: 20px;">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">Request ID</th><th>Resident</th><th>Document</th><th>Status</th><th>Actions</th>
          </tr>
          ${docs.rows.map(d => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${d.request_id}</td>
              <td style="padding: 12px;">${d.full_name}</td>
              <td style="padding: 12px;">${d.document_type}</td>
              <td style="padding: 12px;">${d.status}</td>
              <td style="padding: 12px;">
                <a href="/admin/documents/action/${d.id}/Approved" style="color: #16a34a; margin-right: 10px;">Approve</a>
                <a href="/admin/documents/action/${d.id}/Rejected" style="color: #dc2626; margin-right: 10px;">Reject</a>
                <a href="/admin/documents/print/${d.id}" target="_blank" style="color: #2563eb;">Print/View</a>
              </td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `, req.session));
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
      <body style="font-family: Arial, sans-serif; padding: 40px; max-width: 800px; margin: 0 auto; border: 2px solid #000;">
        <div style="text-align: center;">
          <h2>REPUBLIC OF THE PHILIPPINES</h2>
          <h3>BARANGAY CENTRAL</h3>
          <h1>${d.document_type.toUpperCase()}</h1>
        </div>
        <p style="margin-top: 40px;">TO WHOM IT MAY CONCERN:</p>
        <p style="text-indent: 40px; line-height: 1.8;">This is to certify that <strong>${d.full_name}</strong>, of legal age, is a permanent resident of ${d.address}, and is known to be of good moral character.</p>
        <p style="text-indent: 40px; line-height: 1.8;">This certification is issued upon the request of the above-named person for <strong>${d.purpose}</strong>.</p>
        <p style="margin-top: 50px;">Document Number: <strong>${d.document_number || 'N/A'}</strong></p>
        <div style="float: right; margin-top: 80px; text-align: center;">
          <div style="border-bottom: 1px solid black; width: 200px; margin-bottom: 5px;"></div>
          <strong>BARANGAY CAPTAIN</strong><br>Punong Barangay
        </div>
        <script>window.print();</script>
      </body>
    </html>
  `);
});

// Blotter Management
app.get('/admin/blotter', isAuthenticated, requireRole('admin'), async (req, res) => {
  const blotters = await pool.query('SELECT * FROM blotter_records');
  res.send(renderLayout('Blotter Management', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Blotter Records</h2>
        <form action="/admin/blotter" method="POST" style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
          <h3>Add Blotter Record</h3>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px;">
            <input type="text" name="case_number" placeholder="Case Number" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <input type="text" name="incident_type" placeholder="Incident Type" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <input type="text" name="complainant" placeholder="Complainant" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <input type="text" name="respondent" placeholder="Respondent" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <input type="date" name="incident_date" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <input type="time" name="incident_time" required style="padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <input type="text" name="location" placeholder="Location" required style="grid-column: span 2; padding: 8px; border:1px solid #ccc; border-radius:4px;">
            <textarea name="description" placeholder="Description" required style="grid-column: span 2; padding: 8px; border:1px solid #ccc; border-radius:4px;"></textarea>
          </div>
          <button type="submit" style="margin-top: 10px; padding: 10px 20px; background: #16a34a; color: white; border: none; border-radius: 4px; font-weight: bold;">Save Record</button>
        </form>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px;">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">Case #</th><th>Incident</th><th>Complainant</th><th>Respondent</th><th>Status</th>
          </tr>
          ${blotters.rows.map(b => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${b.case_number}</td>
              <td style="padding: 12px;">${b.incident_type}</td>
              <td style="padding: 12px;">${b.complainant}</td>
              <td style="padding: 12px;">${b.respondent}</td>
              <td style="padding: 12px;">${b.status}</td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `, req.session));
});

app.post('/admin/blotter', isAuthenticated, requireRole('admin'), async (req, res) => {
  const { case_number, complainant, respondent, incident_type, incident_date, incident_time, location, description } = req.body;
  await pool.query(
    `INSERT INTO blotter_records (case_number, complainant, respondent, incident_type, incident_date, incident_time, location, description) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [case_number, complainant, respondent, incident_type, incident_date, incident_time, location, description]
  );
  res.redirect('/admin/blotter');
});

// QR Scanner & Verification Page
app.get('/admin/scanner', isAuthenticated, async (req, res) => {
  res.send(renderLayout('QR Scanner', `
    <div style="display: flex;">
      ${renderSidebar(req.session.user.role)}
      <div style="flex: 1; padding: 20px; background: #f8fafc; text-align: center;">
        <h2>QR Resident ID Verification</h2>
        <p>Enter or scan Resident ID / QR Token to verify status.</p>
        <form method="POST" style="margin-top: 20px;">
          <input type="text" name="qr_token" placeholder="Scan/Enter Resident ID or Code" style="padding: 10px; width: 350px; border: 1px solid #ccc; border-radius: 4px;" required>
          <button type="submit" style="padding: 10px 20px; background: #2563eb; color: white; border: none; border-radius: 4px; font-weight: bold;">Verify</button>
        </form>
      </div>
    </div>
  `, req.session));
});

app.post('/admin/scanner', isAuthenticated, async (req, res) => {
  const { qr_token } = req.body;
  const result = await pool.query('SELECT * FROM residents WHERE resident_id = $1 OR qr_code LIKE $2', [qr_token, `%${qr_token}%`]);
  
  let details = '<p style="color: red;">Resident not found or invalid QR code.</p>';
  if (result.rows.length > 0) {
    const r = result.rows[0];
    details = `
      <div style="background: white; padding: 20px; border-radius: 8px; max-width: 400px; margin: 20px auto; text-align: left; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
        <h3>Resident Verified</h3>
        <p><strong>ID:</strong> ${r.resident_id}</p>
        <p><strong>Name:</strong> ${r.full_name}</p>
        <p><strong>Address:</strong> ${r.address}</p>
        <p><strong>Contact:</strong> ${r.contact_number}</p>
        <p style="color: green; font-weight: bold;">Status: Active / Verified</p>
      </div>
    `;
  }

  res.send(renderLayout('Verification Result', `
    <div style="display: flex;">
      ${renderSidebar(req.session.user.role)}
      <div style="flex: 1; padding: 20px; background: #f8fafc; text-align: center;">
        <h2>Verification Result</h2>
        ${details}
        <a href="/admin/scanner" style="display: inline-block; margin-top: 15px; color: #2563eb;">Scan Another</a>
      </div>
    </div>
  `, req.session));
});

// Announcements & Reports
app.get('/admin/announcements', isAuthenticated, requireRole('admin'), async (req, res) => {
  const announcements = await pool.query('SELECT * FROM announcements ORDER BY created_at DESC');
  res.send(renderLayout('Announcements', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Announcements</h2>
        <form action="/admin/announcements" method="POST" style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
          <h3>Post Announcement</h3>
          <input type="text" name="title" placeholder="Title" required style="width: 100%; padding: 8px; margin-bottom: 10px; border:1px solid #ccc; border-radius:4px;">
          <textarea name="content" placeholder="Content" required style="width: 100%; padding: 8px; margin-bottom: 10px; border:1px solid #ccc; border-radius:4px;"></textarea>
          <button type="submit" style="padding: 10px 20px; background: #16a34a; color: white; border: none; border-radius: 4px; font-weight: bold;">Publish</button>
        </form>
        ${announcements.rows.map(a => `
          <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <h4>${a.title}</h4>
            <p>${a.content}</p>
          </div>
        `).join('')}
      </div>
    </div>
  `, req.session));
});

app.post('/admin/announcements', isAuthenticated, requireRole('admin'), async (req, res) => {
  const { title, content } = req.body;
  await pool.query('INSERT INTO announcements (title, content) VALUES ($1, $2)', [title, content]);
  res.redirect('/admin/announcements');
});

// Activity Logs
app.get('/admin/logs', isAuthenticated, requireRole('admin'), async (req, res) => {
  const logs = await pool.query('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 100');
  res.send(renderLayout('Activity Logs', `
    <div style="display: flex;">
      ${renderSidebar('admin')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Activity Logs</h2>
        <table style="width: 100%; background: white; border-collapse: collapse; border-radius: 8px; margin-top: 20px;">
          <tr style="background: #1e3a8a; color: white; text-align: left;">
            <th style="padding: 12px;">Timestamp</th><th>Username</th><th>Role</th><th>Module</th><th>Action</th>
          </tr>
          ${logs.rows.map(l => `
            <tr style="border-bottom: 1px solid #e2e8f0;">
              <td style="padding: 12px;">${l.created_at.toISOString()}</td>
              <td style="padding: 12px;">${l.username}</td>
              <td style="padding: 12px;">${l.role}</td>
              <td style="padding: 12px;">${l.module}</td>
              <td style="padding: 12px;">${l.action}</td>
            </tr>
          `).join('')}
        </table>
      </div>
    </div>
  `, req.session));
});

// --- STAFF PORTAL ---
app.get('/staff', isAuthenticated, requireRole('staff'), async (req, res) => {
  res.send(renderLayout('Staff Portal', `
    <div style="display: flex;">
      ${renderSidebar('staff')}
      <div style="flex: 1; padding: 20px; background: #f8fafc;">
        <h2>Staff Portal Dashboard</h2>
        <p>Welcome, staff member. Use the sidebar to process documents, view residents, or verify QR IDs.</p>
      </div>
    </div>
  `, req.session));
});

// --- RESIDENT PORTAL ---
app.get('/resident', isAuthenticated, requireRole('resident'), async (req, res) => {
  const residentResult = await pool.query('SELECT * FROM residents WHERE user_id = $1', [req.session.user.id]);
  if (residentResult.rows.length === 0) return res.send('Resident profile not linked.');
  const resident = residentResult.rows[0];

  const requests = await pool.query('SELECT * FROM document_requests WHERE resident_id = $1', [resident.id]);
  const announcements = await pool.query('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 5');

  res.send(renderLayout('Resident Portal', `
    <div style="display: flex; flex-direction: column; min-height: 100vh; background: #f8fafc;">
      <div style="background: #1e3a8a; color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center;">
        <h2>Barangay Resident Portal</h2>
        <div>
          <span style="margin-right: 15px;">Hello, ${resident.full_name}</span>
          <a href="/logout" style="color: white; text-decoration: underline;">Logout</a>
        </div>
      </div>
      <div style="padding: 30px; max-width: 1000px; margin: 0 auto; width: 100%;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <h3>My Resident ID & QR</h3>
            <p><strong>ID:</strong> ${resident.resident_id}</p>
            <div style="text-align: center; margin-top: 15px;">
              <img src="${resident.qr_code}" alt="QR Code" style="width: 150px; height: 150px;">
            </div>
          </div>
          <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
            <h3>Request Document</h3>
            <form action="/resident/request" method="POST">
              <div style="margin-bottom: 10px;">
                <label>Document Type</label>
                <select name="document_type" style="width:150px; width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;">
                  <option>Barangay Clearance</option>
                  <option>Certificate of Residency</option>
                  <option>Certificate of Indigency</option>
                  <option>Business Clearance</option>
                </select>
              </div>
              <div style="margin-bottom: 10px;">
                <label>Purpose</label>
                <input type="text" name="purpose" required style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;">
              </div>
              <button type="submit" style="padding: 10px 20px; background: #2563eb; color: white; border: none; border-radius: 4px; font-weight: bold;">Submit Request</button>
            </form>
          </div>
        </div>
        
        <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
          <h3>My Requests History</h3>
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
  `, req.session));
});

app.post('/resident/request', isAuthenticated, requireRole('resident'), async (req, res) => {
  const { document_type, purpose } = req.body;
  const residentRes = await pool.query('SELECT id FROM residents WHERE user_id = $1', [req.session.user.id]);
  if (residentRes.rows.length === 0) return res.send('Resident profile not found.');
  const residentId = residentRes.rows[0].id;

  const requestId = `REQ-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
  await pool.query(
    `INSERT INTO document_requests (request_id, resident_id, document_type, purpose) VALUES ($1, $2, $3, $4)`,
    [requestId, residentId, document_type, purpose]
  );
  res.redirect('/resident');
});

// --- HELPER LAYOUT & UI RENDERERS ---
function renderLayout(title, content, session) {
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
    <a href="/admin/households" style="color: white; display: block; padding: 10px 0;">Households</a>
    <a href="/admin/users" style="color: white; display: block; padding: 10px 0;">User Accounts</a>
    <a href="/admin/documents" style="color: white; display: block; padding: 10px 0;">Documents</a>
    <a href="/admin/blotter" style="color: white; display: block; padding: 10px 0;">Blotter</a>
    <a href="/admin/announcements" style="color: white; display: block; padding: 10px 0;">Announcements</a>
    <a href="/admin/scanner" style="color: white; display: block; padding: 10px 0;">QR Scanner</a>
    <a href="/admin/logs" style="color: white; display: block; padding: 10px 0;">Activity Logs</a>
  ` : `
    <a href="/staff" style="color: white; display: block; padding: 10px 0;">Dashboard</a>
    <a href="/admin/scanner" style="color: white; display: block; padding: 10px 0;">QR Scanner</a>
  `;

  return `
    <div style="width: 250px; background: #1e3a8a; color: white; min-height: 100vh; padding: 20px;">
      <h3 style="margin-bottom: 20px; border-bottom: 1px solid #3b82f6; padding-bottom: 10px;">Barangay Portal</h3>
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

// --- SERVER STARTUP ---
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});