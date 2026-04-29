const express = require('express');
const Database = require('better-sqlite3');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

// Multer config for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomBytes(8).toString('hex');
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|pdf|doc|docx|xls|xlsx|txt|mp3|mp4|wav/;
    const ext = allowed.test(path.extname(file.originalname).toLowerCase());
    if (ext) cb(null, true);
    else cb(new Error('Tipe file tidak didukung'));
  }
});

// Database setup
const db = new Database(path.join(__dirname, 'whistleblowing.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT UNIQUE NOT NULL,
    category TEXT NOT NULL,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    location TEXT,
    date_incident TEXT,
    status TEXT DEFAULT 'pending',
    admin_notes TEXT DEFAULT '',
    anonymous_hash TEXT NOT NULL,
    ip_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_size INTEGER,
    mime_type TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS report_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    sender TEXT NOT NULL DEFAULT 'reporter',
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM admins WHERE username = ?').get('admin');
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO admins (username, password) VALUES (?, ?)').run('admin', hashedPassword);
  console.log('Default admin created - username: admin, password: admin123');
}

// Helper: generate ticket ID
function generateTicketId() {
  const prefix = 'WB';
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${prefix}-${timestamp}-${random}`;
}

// Helper: generate anonymous hash (for tracking without revealing identity)
function generateAnonymousHash() {
  return crypto.randomBytes(16).toString('hex');
}

// Helper: hash IP for anonymous tracking
function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + 'whistleblowing-salt-2024').digest('hex').substring(0, 16);
}

// ============ API ROUTES ============

// Submit a new report
app.post('/api/reports', upload.array('attachments', 5), (req, res) => {
  try {
    const { category, subject, description, severity, location, date_incident } = req.body;

    if (!category || !subject || !description) {
      return res.status(400).json({ error: 'Kategori, subjek, dan deskripsi wajib diisi' });
    }

    const ticket_id = generateTicketId();
    const anonymous_hash = generateAnonymousHash();
    const ip_hash = hashIP(req.ip || req.connection.remoteAddress);

    const stmt = db.prepare(`
      INSERT INTO reports (ticket_id, category, subject, description, severity, location, date_incident, anonymous_hash, ip_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(ticket_id, category, subject, description, severity || 'medium', location || '', date_incident || '', anonymous_hash, ip_hash);

    // Handle file attachments
    if (req.files && req.files.length > 0) {
      const attachStmt = db.prepare(`
        INSERT INTO attachments (report_id, filename, original_name, file_size, mime_type)
        VALUES (?, ?, ?, ?, ?)
      `);
      for (const file of req.files) {
        attachStmt.run(result.lastInsertRowid, file.filename, file.originalname, file.size, file.mimetype);
      }
    }

    res.json({
      success: true,
      ticket_id,
      anonymous_hash,
      message: 'Laporan berhasil dikirim secara anonim'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengirim laporan' });
  }
});

// Track report by ticket ID
app.get('/api/reports/track/:ticketId', (req, res) => {
  try {
    const report = db.prepare(`
      SELECT ticket_id, category, subject, status, severity, created_at, updated_at, admin_notes
      FROM reports WHERE ticket_id = ?
    `).get(req.params.ticketId);

    if (!report) {
      return res.status(404).json({ error: 'Laporan tidak ditemukan' });
    }

    const messages = db.prepare(`
      SELECT sender, message, created_at FROM report_messages
      WHERE report_id = (SELECT id FROM reports WHERE ticket_id = ?)
      ORDER BY created_at ASC
    `).all(req.params.ticketId);

    res.json({ ...report, messages });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengambil data laporan' });
  }
});

// Reporter sends follow-up message
app.post('/api/reports/track/:ticketId/message', (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Pesan tidak boleh kosong' });

    const report = db.prepare('SELECT id FROM reports WHERE ticket_id = ?').get(req.params.ticketId);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });

    db.prepare('INSERT INTO report_messages (report_id, sender, message) VALUES (?, ?, ?)')
      .run(report.id, 'reporter', message);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengirim pesan' });
  }
});

// ============ ADMIN API ROUTES ============

// Admin login
app.post('/api/admin/login', (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);

    if (!admin || !bcrypt.compareSync(password, admin.password)) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    // Simple token (in production, use JWT)
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ success: true, token, username: admin.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login gagal' });
  }
});

// Get all reports (admin)
app.get('/api/admin/reports', (req, res) => {
  try {
    const { status, category, search, sort } = req.query;
    let query = 'SELECT * FROM reports WHERE 1=1';
    const params = [];

    if (status && status !== 'all') {
      query += ' AND status = ?';
      params.push(status);
    }
    if (category && category !== 'all') {
      query += ' AND category = ?';
      params.push(category);
    }
    if (search) {
      query += ' AND (subject LIKE ? OR description LIKE ? OR ticket_id LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += sort === 'oldest' ? ' ORDER BY created_at ASC' : ' ORDER BY created_at DESC';

    const reports = db.prepare(query).all(...params);

    // Get attachment counts
    for (const report of reports) {
      report.attachment_count = db.prepare('SELECT COUNT(*) as count FROM attachments WHERE report_id = ?').get(report.id).count;
      report.message_count = db.prepare('SELECT COUNT(*) as count FROM report_messages WHERE report_id = ?').get(report.id).count;
    }

    res.json(reports);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengambil data laporan' });
  }
});

// Get single report detail (admin)
app.get('/api/admin/reports/:id', (req, res) => {
  try {
    const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });

    const attachments = db.prepare('SELECT * FROM attachments WHERE report_id = ?').all(report.id);
    const messages = db.prepare('SELECT * FROM report_messages WHERE report_id = ? ORDER BY created_at ASC').all(report.id);

    res.json({ ...report, attachments, messages });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengambil detail laporan' });
  }
});

// Update report status (admin)
app.put('/api/admin/reports/:id', (req, res) => {
  try {
    const { status, admin_notes } = req.body;
    const report = db.prepare('SELECT id FROM reports WHERE id = ?').get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });

    if (status) {
      db.prepare('UPDATE reports SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(status, req.params.id);
    }
    if (admin_notes !== undefined) {
      db.prepare('UPDATE reports SET admin_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(admin_notes, req.params.id);
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal memperbarui laporan' });
  }
});

// Admin sends message to reporter
app.post('/api/admin/reports/:id/message', (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Pesan tidak boleh kosong' });

    const report = db.prepare('SELECT id FROM reports WHERE id = ?').get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });

    db.prepare('INSERT INTO report_messages (report_id, sender, message) VALUES (?, ?, ?)')
      .run(report.id, 'admin', message);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengirim pesan' });
  }
});

// Delete report (admin)
app.delete('/api/admin/reports/:id', (req, res) => {
  try {
    // Delete associated files
    const attachments = db.prepare('SELECT filename FROM attachments WHERE report_id = ?').all(req.params.id);
    for (const att of attachments) {
      const filePath = path.join(uploadsDir, att.filename);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    db.prepare('DELETE FROM attachments WHERE report_id = ?').run(req.params.id);
    db.prepare('DELETE FROM report_messages WHERE report_id = ?').run(req.params.id);
    db.prepare('DELETE FROM reports WHERE id = ?').run(req.params.id);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal menghapus laporan' });
  }
});

// Dashboard stats
app.get('/api/admin/stats', (req, res) => {
  try {
    const total = db.prepare('SELECT COUNT(*) as count FROM reports').get().count;
    const pending = db.prepare("SELECT COUNT(*) as count FROM reports WHERE status = 'pending'").get().count;
    const investigating = db.prepare("SELECT COUNT(*) as count FROM reports WHERE status = 'investigating'").get().count;
    const resolved = db.prepare("SELECT COUNT(*) as count FROM reports WHERE status = 'resolved'").get().count;
    const dismissed = db.prepare("SELECT COUNT(*) as count FROM reports WHERE status = 'dismissed'").get().count;

    const byCategory = db.prepare('SELECT category, COUNT(*) as count FROM reports GROUP BY category').all();
    const bySeverity = db.prepare('SELECT severity, COUNT(*) as count FROM reports GROUP BY severity').all();

    const recentReports = db.prepare('SELECT ticket_id, subject, category, severity, status, created_at FROM reports ORDER BY created_at DESC LIMIT 5').all();

    res.json({ total, pending, investigating, resolved, dismissed, byCategory, bySeverity, recentReports });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengambil statistik' });
  }
});

// Change admin password
app.put('/api/admin/change-password', (req, res) => {
  try {
    const { username, oldPassword, newPassword } = req.body;
    if (!username || !oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Semua field wajib diisi' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password baru minimal 6 karakter' });
    }

    const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
    if (!admin || !bcrypt.compareSync(oldPassword, admin.password)) {
      return res.status(401).json({ error: 'Password lama salah' });
    }

    const hashed = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE admins SET password = ? WHERE username = ?').run(hashed, username);
    res.json({ success: true, message: 'Password berhasil diubah' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Gagal mengubah password' });
  }
});

// Catch-all: serve index.html for SPA-style routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🛡️  Whistleblowing Platform running at http://localhost:${PORT}`);
  console.log(`📋 Admin Panel: http://localhost:${PORT}/admin.html`);
  console.log(`   Default login - username: admin, password: admin123`);
});
