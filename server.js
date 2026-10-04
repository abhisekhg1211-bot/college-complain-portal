const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sgi-sagar-group-secret-key-2026';

// Admin Default Credentials
const ADMIN_USERNAME = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'sgi@admin2026';
// Pre-hash password for secure verification
const ADMIN_HASHED_PASS = bcrypt.hashSync(ADMIN_PASSWORD, 10);

// Paths
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'complaints.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Setup multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const safeName = `proof-${Date.now()}-${Math.round(Math.random() * 1e5)}${ext}`;
    cb(null, safeName);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp|pdf|docx|doc|txt/;
    const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
    if (allowed.test(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Allowed: JPG, PNG, WEBP, PDF, DOCX, TXT'));
    }
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

// Helper functions for persistent data
function getComplaints() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(DATA_FILE, '[]', 'utf8');
      return [];
    }
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading complaints:', err);
    return [];
  }
}

function saveComplaints(complaints) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(complaints, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error saving complaints:', err);
    return false;
  }
}

// Generate Unique Tracking ID: SGI-CMP-2026-XXXX
function generateTrackingId() {
  const year = new Date().getFullYear();
  const randomNum = Math.floor(1000 + Math.random() * 9000);
  return `SGI-CMP-${year}-${randomNum}`;
}

// JWT Admin Auth Middleware
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Access denied. Administrator token required.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded && decoded.role === 'admin') {
      req.admin = decoded;
      return next();
    }
    return res.status(403).json({ success: false, message: 'Forbidden. Unauthorized administrative privilege.' });
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Session expired or invalid token. Please log in again.' });
  }
}

// ==========================================
// PUBLIC STUDENT API ENDPOINTS
// ==========================================

// 1. Submit a complaint
app.post('/api/complaints', upload.single('attachment'), (req, res) => {
  try {
    const {
      studentName,
      rollNo,
      department,
      semester,
      email,
      phone,
      category,
      priority,
      isAnonymous,
      subject,
      description
    } = req.body;

    if (!category || !subject || !description) {
      return res.status(400).json({
        success: false,
        message: 'Category, subject, and detailed description are required.'
      });
    }

    const anonymousBool = isAnonymous === 'true' || isAnonymous === true;

    // Check non-anonymous required fields
    if (!anonymousBool && (!studentName || !rollNo || !email)) {
      return res.status(400).json({
        success: false,
        message: 'Student name, roll number, and email are required for non-anonymous submissions.'
      });
    }

    let attachmentUrl = null;
    let attachmentOriginalName = null;
    if (req.file) {
      attachmentUrl = `/uploads/${req.file.filename}`;
      attachmentOriginalName = req.file.originalname;
    }

    const complaints = getComplaints();
    let trackingId = generateTrackingId();
    // Ensure unique ID
    while (complaints.some(c => c.id === trackingId)) {
      trackingId = generateTrackingId();
    }

    const now = new Date().toISOString();
    const newComplaint = {
      id: trackingId,
      createdAt: now,
      updatedAt: now,
      studentName: anonymousBool ? 'Anonymous Student' : (studentName || 'Student').trim(),
      rollNo: anonymousBool ? 'CONFIDENTIAL' : (rollNo || '').trim(),
      department: department || 'General',
      semester: semester || 'N/A',
      email: anonymousBool ? 'confidential@sgi.local' : (email || '').trim(),
      phone: anonymousBool ? 'PROTECTED' : (phone || '').trim(),
      category: category.trim(),
      priority: priority || 'Normal',
      isAnonymous: anonymousBool,
      subject: subject.trim(),
      description: description.trim(),
      status: 'Pending',
      assignedTo: 'Pending Assignment',
      adminRemarks: 'Your grievance has been safely received by the Sagar Group of Institutions Grievance Cell and is queued for verification.',
      internalNotes: '',
      attachmentUrl,
      attachmentOriginalName,
      timeline: [
        {
          status: 'Submitted',
          timestamp: now,
          comment: 'Grievance submitted by student.'
        }
      ]
    };

    complaints.unshift(newComplaint);
    saveComplaints(complaints);

    return res.status(201).json({
      success: true,
      message: 'Complaint lodged successfully.',
      trackingId: newComplaint.id,
      complaint: {
        id: newComplaint.id,
        category: newComplaint.category,
        subject: newComplaint.subject,
        createdAt: newComplaint.createdAt,
        status: newComplaint.status
      }
    });
  } catch (error) {
    console.error('Error submitting complaint:', error);
    return res.status(500).json({ success: false, message: 'Server error while submitting complaint.' });
  }
});

// 2. Track complaint status by Tracking ID or Roll No
app.get('/api/complaints/track/:trackingId', (req, res) => {
  try {
    const query = req.params.trackingId.trim().toUpperCase();
    const complaints = getComplaints();

    // Match exact Tracking ID or Roll No
    const found = complaints.find(c => c.id.toUpperCase() === query || (!c.isAnonymous && c.rollNo.toUpperCase() === query));

    if (!found) {
      return res.status(404).json({
        success: false,
        message: `No grievance found matching reference '${query}'. Please check your Tracking ID.`
      });
    }

    // Return sanitized public tracking view
    const safeData = {
      id: found.id,
      createdAt: found.createdAt,
      updatedAt: found.updatedAt,
      category: found.category,
      subject: found.subject,
      description: found.description,
      priority: found.priority,
      status: found.status,
      assignedTo: found.assignedTo,
      adminRemarks: found.adminRemarks,
      attachmentUrl: found.attachmentUrl,
      attachmentOriginalName: found.attachmentOriginalName,
      isAnonymous: found.isAnonymous,
      studentName: found.isAnonymous ? 'Anonymous Student' : found.studentName,
      rollNo: found.isAnonymous ? 'CONFIDENTIAL' : found.rollNo,
      department: found.department,
      semester: found.semester,
      timeline: found.timeline || []
    };

    return res.json({ success: true, complaint: safeData });
  } catch (error) {
    console.error('Error tracking complaint:', error);
    return res.status(500).json({ success: false, message: 'Server error while fetching complaint.' });
  }
});

// ==========================================
// ADMIN AUTHENTICATION & MANAGEMENT ENDPOINTS
// ==========================================

// 1. Admin Login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  const isUserMatch = username.trim().toLowerCase() === ADMIN_USERNAME.toLowerCase();
  const isPassMatch = isUserMatch && (password === ADMIN_PASSWORD || bcrypt.compareSync(password, ADMIN_HASHED_PASS));

  if (!isPassMatch) {
    return res.status(401).json({ success: false, message: 'Invalid admin username or password.' });
  }

  // Issue JWT Token
  const token = jwt.sign(
    {
      role: 'admin',
      username: ADMIN_USERNAME,
      college: 'Sagar Group of Institutions',
      institutionCode: 'SGI-BPL'
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  return res.json({
    success: true,
    message: 'Admin authentication successful.',
    token,
    admin: {
      username: ADMIN_USERNAME,
      role: 'System Administrator',
      college: 'Sagar Group of Institutions'
    }
  });
});

// 2. Admin Verify Token
app.get('/api/admin/verify', verifyAdmin, (req, res) => {
  return res.json({
    success: true,
    valid: true,
    admin: req.admin
  });
});

// 3. Admin Get Statistics
app.get('/api/admin/stats', verifyAdmin, (req, res) => {
  try {
    const complaints = getComplaints();

    const stats = {
      total: complaints.length,
      pending: complaints.filter(c => c.status === 'Pending').length,
      underReview: complaints.filter(c => c.status === 'Under Review').length,
      inProgress: complaints.filter(c => c.status === 'In Progress').length,
      resolved: complaints.filter(c => c.status === 'Resolved').length,
      rejected: complaints.filter(c => c.status === 'Rejected').length,
      urgent: complaints.filter(c => c.priority === 'Urgent').length,
      byCategory: {},
      byDepartment: {},
      recentActivity: complaints.slice(0, 5)
    };

    complaints.forEach(c => {
      stats.byCategory[c.category] = (stats.byCategory[c.category] || 0) + 1;
      if (c.department && c.department !== 'General') {
        stats.byDepartment[c.department] = (stats.byDepartment[c.department] || 0) + 1;
      }
    });

    return res.json({ success: true, stats });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Error calculating stats.' });
  }
});

// 4. Admin Get All Complaints (with filtering, search, pagination)
app.get('/api/admin/complaints', verifyAdmin, (req, res) => {
  try {
    let complaints = getComplaints();
    const { status, category, priority, search } = req.query;

    if (status && status !== 'all') {
      complaints = complaints.filter(c => c.status.toLowerCase() === status.toLowerCase());
    }

    if (category && category !== 'all') {
      complaints = complaints.filter(c => c.category.toLowerCase() === category.toLowerCase());
    }

    if (priority && priority !== 'all') {
      complaints = complaints.filter(c => c.priority.toLowerCase() === priority.toLowerCase());
    }

    if (search) {
      const q = search.toLowerCase();
      complaints = complaints.filter(c =>
        c.id.toLowerCase().includes(q) ||
        (c.studentName && c.studentName.toLowerCase().includes(q)) ||
        (c.rollNo && c.rollNo.toLowerCase().includes(q)) ||
        (c.subject && c.subject.toLowerCase().includes(q)) ||
        (c.description && c.description.toLowerCase().includes(q)) ||
        (c.department && c.department.toLowerCase().includes(q))
      );
    }

    return res.json({
      success: true,
      count: complaints.length,
      complaints
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Error fetching complaints.' });
  }
});

// 5. Admin Update Complaint Status, Remarks, Assigned Authority
app.put('/api/admin/complaints/:id/status', verifyAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminRemarks, assignedTo, internalNotes } = req.body;

    const complaints = getComplaints();
    const index = complaints.findIndex(c => c.id === id);

    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Grievance ticket not found.' });
    }

    const complaint = complaints[index];
    const now = new Date().toISOString();

    if (status && status !== complaint.status) {
      complaint.status = status;
      // Add entry to history timeline
      complaint.timeline.push({
        status: status,
        timestamp: now,
        comment: adminRemarks || `Status changed to ${status} by Administrator.`
      });
    }

    if (adminRemarks !== undefined) complaint.adminRemarks = adminRemarks;
    if (assignedTo !== undefined) complaint.assignedTo = assignedTo;
    if (internalNotes !== undefined) complaint.internalNotes = internalNotes;
    complaint.updatedAt = now;

    complaints[index] = complaint;
    saveComplaints(complaints);

    return res.json({
      success: true,
      message: `Grievance #${id} updated successfully.`,
      complaint
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to update complaint status.' });
  }
});

// 6. Admin Delete Complaint
app.delete('/api/admin/complaints/:id', verifyAdmin, (req, res) => {
  try {
    const { id } = req.params;
    let complaints = getComplaints();
    const prevLen = complaints.length;

    complaints = complaints.filter(c => c.id !== id);

    if (complaints.length === prevLen) {
      return res.status(404).json({ success: false, message: 'Complaint not found.' });
    }

    saveComplaints(complaints);
    return res.json({ success: true, message: `Complaint #${id} deleted successfully.` });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to delete complaint.' });
  }
});

// 7. Admin Export to CSV
app.get('/api/admin/export/csv', verifyAdmin, (req, res) => {
  try {
    const complaints = getComplaints();
    const headers = [
      'Tracking ID',
      'Date Submitted',
      'Student Name',
      'Roll Number',
      'Department',
      'Semester',
      'Email',
      'Phone',
      'Category',
      'Priority',
      'Status',
      'Assigned To',
      'Subject',
      'Description',
      'Admin Remarks'
    ];

    const rows = complaints.map(c => [
      `"${c.id}"`,
      `"${c.createdAt}"`,
      `"${c.studentName}"`,
      `"${c.rollNo}"`,
      `"${c.department}"`,
      `"${c.semester}"`,
      `"${c.email}"`,
      `"${c.phone}"`,
      `"${c.category}"`,
      `"${c.priority}"`,
      `"${c.status}"`,
      `"${c.assignedTo}"`,
      `"${(c.subject || '').replace(/"/g, '""')}"`,
      `"${(c.description || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`,
      `"${(c.adminRemarks || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=SGI_Grievances_${Date.now()}.csv`);
    return res.send(csvContent);
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Error exporting CSV.' });
  }
});

// SPA Catch-all route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`SAGAR GROUP OF INSTITUTIONS - STUDENT GRIEVANCE PORTAL`);
  console.log(`Server running at: http://localhost:${PORT}`);
  console.log(`Admin credentials: username="${ADMIN_USERNAME}" | password="${ADMIN_PASSWORD}"`);
  console.log(`=======================================================`);
});
