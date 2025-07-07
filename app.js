const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto'); // For calculating SHA-256 hash

const app = express();
const port = 3000;

// Replace with your actual JWT secret key
const JWT_SECRET = 'your_super_secret_jwt_key'; // ENSURE THIS IS THE SAME AS IN LOGIN AND REGISTER

// MySQL database connection pool configuration
const pool = mysql.createPool({
  connectionLimit: 10, // Maximum number of connections to open
  host: 'localhost', // Replace with your database host
  user: 'root',      // Replace with your database user
  password: '',      // Replace with your database password
  database: 'cryptdocs_db', // Replace with your database name
});

console.log('--- app.js startup ---');
console.log('Is pool defined immediately after creation (top-level)?', typeof pool !== 'undefined' && pool !== null);

// Test pool connection before starting the server
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database pool connection error:', err);
    if (connection) connection.release(); // Ensure connection is released if obtained
    process.exit(1); // Exit with error code if database connection fails
  }
  console.log('Connected to the database pool. Testing connection...');
  connection.release(); // Release connection after testing
  
  // Only start listening for requests after database connection is successfully tested
  app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
});

// Middleware
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public')); // For serving static files like HTML, CSS, JS
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // For serving files from the 'uploads' folder

// ====================================================================
// NEW TABLE SCHEMA (YOU NEED TO RUN THIS IN YOUR MYSQL DATABASE)
// ====================================================================
/*
-- Pastikan tabel 'users' memiliki kolom 'full_name'
ALTER TABLE users ADD COLUMN full_name VARCHAR(255) DEFAULT NULL;

-- Contoh lengkap skema tabel users (jika belum ada)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'Employee',
    profile_picture VARCHAR(255) DEFAULT NULL,
    division VARCHAR(255) DEFAULT NULL,
    full_name VARCHAR(255) DEFAULT NULL -- Kolom baru untuk nama lengkap
);

CREATE TABLE IF NOT EXISTS recently_opened_documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    document_id INT NOT NULL, -- ID from sent_documents or received_documents
    file_name VARCHAR(255) NOT NULL,
    document_type ENUM('sent', 'received') NOT NULL, -- Document type (sent/received)
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX(user_email, opened_at)
);

-- Ensure the 'activity_log' table exists
CREATE TABLE IF NOT EXISTS activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    details JSON,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Pastikan tabel 'sent_documents' memiliki kolom 'status' dan 'sender_id'
-- ALTER TABLE sent_documents ADD COLUMN status VARCHAR(50) DEFAULT 'Sent';
-- ALTER TABLE sent_documents ADD COLUMN sender_id INT;
-- UPDATE sent_documents sd JOIN users u ON sd.sender_email = u.email SET sd.sender_id = u.id WHERE sd.sender_id IS NULL;
-- Atau jika belum ada tabelnya:
CREATE TABLE IF NOT EXISTS sent_documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    division VARCHAR(255),
    receiver VARCHAR(255),
    comment TEXT,
    hash_sha256 VARCHAR(64) UNIQUE NOT NULL,
    sender_email VARCHAR(255) NOT NULL,
    sender_id INT NOT NULL, -- Tambahkan sender_id
    sent_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    deleted BOOLEAN DEFAULT FALSE,
    deleted_at DATETIME DEFAULT NULL,
    status VARCHAR(50) DEFAULT 'Sent' -- Tambahkan kolom status
);

-- Pastikan tabel 'received_documents' memiliki kolom 'status'
-- ALTER TABLE received_documents ADD COLUMN status VARCHAR(50) DEFAULT 'Belum Dibaca';
-- Atau jika belum ada tabelnya:
CREATE TABLE IF NOT EXISTS received_documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    sender_email VARCHAR(255) NOT NULL,
    receiver_email VARCHAR(255) NOT NULL,
    received_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'Belum Dibaca', -- Tambahkan kolom status
    comment TEXT,
    hash_sha256 VARCHAR(64) UNIQUE NOT NULL,
    deleted BOOLEAN DEFAULT FALSE,
    deleted_at DATETIME DEFAULT NULL
);
*/

// Function to log activity to the database
async function logActivity(userEmail, action, details) {
  return new Promise((resolve, reject) => {
    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in logActivity.');
      return reject(new Error('Database pool not initialized for logging.'));
    }
    pool.getConnection((err, connection) => {
      if (err) {
        console.error('Error getting database connection for logging activity:', err);
        return reject(new Error('Database connection not available for logging.'));
      }

      const query = 'INSERT INTO activity_log (user_email, action, details, timestamp) VALUES (?, ?, ?, NOW())';
      connection.query(query, [userEmail, action, JSON.stringify(details)], (err, result) => {
        connection.release(); // Always release the connection after completion
        if (err) {
          console.error('Error logging activity:', err);
          reject(err);
        } else {
          console.log(`Activity logged: ${action} by ${userEmail}`);
          resolve(result);
        }
      });
    });
  });
}

// Middleware for JWT token authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                console.error("JWT Verification Error:", err);
                // If token is invalid or expired, send 403
                return res.status(403).json({ error: 'Invalid token or token expired' });
            }
            req.user = user;

            // Logic for sliding session: refresh token if close to expiration
            const now = Math.floor(Date.now() / 1000); // Current time in seconds
            const expirationTime = user.exp; // Expiration time from token payload
            const timeLeft = expirationTime - now; // Time left in seconds

            // If time left is less than 10 minutes (600 seconds), issue a new token
            if (timeLeft < (10 * 60)) { 
                console.log('Token is about to expire, issuing new token...');
                const newPayload = {
                    userId: user.userId,
                    email: user.email,
                    username: user.email, // This is still email, but will be replaced by full_name in frontend display
                    profilePicture: user.profilePicture,
                    role: user.role,
                    division: user.division,
                    full_name: user.full_name // Include full_name in new token payload
                };
                const newToken = jwt.sign(newPayload, JWT_SECRET, { expiresIn: '1h' }); // New token valid for 1 hour
                res.setHeader('X-New-Token', newToken); // Send new token in custom header
                console.log('New token issued and set in X-New-Token header.');
            }

            console.log('authenticateToken: User email from token:', req.user.email); // Debugging
            next();
        });
    } else {
        return res.status(401).json({ error: 'Token not provided' });
    }
}

// Middleware for Admin authorization
function authorizeAdmin(req, res, next) {
    if (req.user && req.user.role === 'Administrator') {
        next();
    } else {
        res.status(403).json({ message: 'Access denied: You are not an Administrator.' });
    }
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads'); // Change to 'uploads'
        fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname); // Use original file name
    },
});
const upload = multer({ storage: storage });

// Register Route (Default role 'Employee')
app.post("/register", (req, res) => {
    // Destructure full_name, division from req.body
    const { employee_id, email, password, division, full_name } = req.body; 
    const role = 'Employee'; // Set default role for all new registrants

    // --- NEW: Log received division and full_name value for debugging ---
    console.log(`Register attempt for email: ${email}, received division: "${division}", full_name: "${full_name}"`);
    // --- END NEW ---

    // Validate if all fields are filled, including division and full_name
    if (!employee_id || !email || !password || !division || !full_name) {
        return res.status(400).json({ message: "Semua field harus diisi!" });
    }

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /register route.');
      return res.status(500).json({ message: "Server error: Database pool not initialized." });
    }

    pool.getConnection(async (err, connection) => { // Add async here
      if (err) {
        console.error('Error getting database connection for register:', err);
        return res.status(500).json({ message: "Server error: Database connection failed." });
      }

      try {
        // Check if email is already registered
        const [emailCheck] = await connection.promise().query("SELECT id FROM users WHERE email = ?", [email]);
        if (emailCheck.length > 0) {
            connection.release();
            // Specific message for already registered email
            return res.status(409).json({ message: "Email sudah terdaftar. Silakan gunakan email lain." });
        }

        // Check if employee_id is already registered
        const [employeeIdCheck] = await connection.promise().query("SELECT id FROM users WHERE employee_id = ?", [employee_id]);
        if (employeeIdCheck.length > 0) {
            connection.release();
            // Specific message for already registered Employee ID
            return res.status(409).json({ message: "Employee ID sudah terdaftar. Silakan gunakan Employee ID lain." });
        }

        // If email and employee_id are unique, proceed with registration
        // Include 'division' and 'full_name' in the INSERT query
        const sql = "INSERT INTO users (employee_id, email, password, role, division, full_name) VALUES (?, ?, ?, ?, ?, ?)";
        const params = [employee_id, email, password, role, division, full_name];

        // --- NEW: Log the exact SQL query and parameters for debugging ---
        console.log("Executing SQL:", sql);
        console.log("With parameters:", params);
        // --- END NEW ---

        const [result] = await connection.promise().query(sql, params); 
        
        console.log("User registered:", result.insertId);
        logActivity(email, 'Register', { role: role, division: division, full_name: full_name }); // Also log the full_name
        res.status(201).json({ message: "Registrasi berhasil! Silakan login." });

      } catch (dbError) {
          console.error("Register error:", dbError);
          res.status(500).json({ message: "Gagal registrasi user", error: dbError.message });
      } finally {
          connection.release(); // Ensure connection is released at the end
      }
    });
});

// Login Route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    console.log('Login attempt:', email);

    if (!email || !password) {
        return res.status(400).json({ message: "Email dan password harus diisi!" });
    }

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /login route.');
      return res.status(500).json({ message: "Server error: Database pool not initialized." });
    }

    pool.getConnection(async (err, connection) => {
      if (err) {
        console.error('Error getting database connection for login:', err);
        return res.status(500).json({ message: "Server error: Database connection failed." });
      }

      // Select full_name, division as well
      const sql = "SELECT id, employee_id, email, profile_picture, role, division, full_name FROM users WHERE email = ? AND password = ?";
      connection.query(sql, [email, password], async (err, results) => {
          connection.release();
          if (err) {
              console.error("Login error:", err);
              return res.status(500).json({ message: "Server error", error: err.message });
          }
          
          if (results.length > 0) {
              const user = results[0];
              const payload = {
                  userId: user.id,
                  email: user.email,
                  username: user.email, // Still keep email for 'username' claim for backward compatibility if needed
                  profilePicture: user.profile_picture,
                  role: user.role,
                  division: user.division,
                  full_name: user.full_name // Include full_name in JWT payload
              };

              const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

              try {
                  await logActivity(email, 'Login', {});
                  res.json({ token });
              } catch (logError) {
                  console.error("Error logging login activity:", logError);
                  res.json({ token, message: "Login successful, but activity log failed." });
              }
          } else {
              res.status(401).json({ message: "Email atau password salah!" });
          }
      });
    });
});

// File Upload Route
app.post("/upload", authenticateToken, upload.single("file"), async (req, res) => { // Add 'async' here
    const { division, receiver, comment } = req.body;
    const file = req.file;
    const senderEmail = req.user.email;
    const senderId = req.user.userId; // Get sender_id from JWT

    if (!file) {
        return res.status(400).json({ message: "File tidak ditemukan!" });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /upload route.');
        return res.status(500).json({ message: "Server error: Database pool not initialized." });
    }

    let fileHash;
    try {
        // Read file to calculate hash
        const fileContent = fs.readFileSync(file.path);
        fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');
        console.log(`File hash for ${file.originalname}: ${fileHash}`);
    } catch (hashError) {
        console.error("Error calculating file hash:", hashError);
        return res.status(500).json({ message: "Gagal menghitung hash file." });
    }

    pool.getConnection(async (err, connection) => { // Use async connection
        if (err) {
            console.error('Error getting database connection for upload:', err);
            return res.status(500).json({ message: "Server error: Database connection failed." });
        }

        try {
            // 1. Check if a file with the same hash already exists in sent_documents
            const checkSentHashQuery = "SELECT id, file_name FROM sent_documents WHERE hash_sha256 = ? LIMIT 1";
            const [existingSentFiles] = await connection.promise().query(checkSentHashQuery, [fileHash]);

            // 2. Check if a file with the same hash already exists in received_documents
            const checkReceivedHashQuery = "SELECT id, file_name FROM received_documents WHERE hash_sha256 = ? LIMIT 1";
            const [existingReceivedFiles] = await connection.promise().query(checkReceivedHashQuery, [fileHash]);

            let isDuplicate = false;
            let duplicateFileName = '';

            if (existingSentFiles.length > 0) {
                isDuplicate = true;
                duplicateFileName = existingSentFiles[0].file_name;
            } else if (existingReceivedFiles.length > 0) {
                isDuplicate = true;
                duplicateFileName = existingReceivedFiles[0].file_name;
            }

            if (isDuplicate) {
                // If duplicate, delete the newly uploaded file because we won't save it
                fs.unlink(file.path, (unlinkErr) => {
                    if (unlinkErr) console.error("Error deleting duplicate uploaded file:", unlinkErr);
                    else console.log(`Duplicate file ${file.originalname} deleted from uploads.`);
                });
                connection.release();
                // Provide information that the file is a duplicate and already exists
                return res.status(200).json({
                    message: `File already uploaded: ${duplicateFileName}`,
                    hash: fileHash,
                    status: 'duplicate'
                });
            }

            // If not duplicate, proceed to save to database
            const sqlSent = `
                INSERT INTO sent_documents (file_name, division, receiver, comment, hash_sha256, sender_email, sender_id, sent_date, deleted, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), 0, 'Sent')
            `;

            const [resultSent] = await connection.promise().query(sqlSent, [file.originalname, division, receiver, comment, fileHash, senderEmail, senderId]);
            console.log("File uploaded and saved to sent_documents:", resultSent.insertId);

            // Upload Activity Log
            const logDetails = {
                fileName: file.originalname,
                division,
                receiver,
                comment,
                hash_sha256: fileHash
            };
            logActivity(senderEmail, 'Upload', logDetails);

            // Save to received_documents (assuming receiver also records)
            const sqlReceived = `
                INSERT INTO received_documents (file_name, sender_email, receiver_email, received_date, status, comment, hash_sha256, deleted)
                VALUES (?, ?, ?, NOW(), ?, ?, ?, 0)
            `;
            // Changed 'Belum Dibaca' to 'Sent' for initial received status
            const [resultReceived] = await connection.promise().query(sqlReceived, [file.originalname, senderEmail, receiver, 'Sent', comment, fileHash]);
            console.log("File recorded as received:", resultReceived.insertId);

            res.status(200).json({
                message: "File berhasil dikirim!",
                hash: fileHash,
                status: 'uploaded'
            });

        } catch (dbError) {
            console.error("Error during file upload and DB operations:", dbError);
            // Delete the uploaded file if a database error occurs
            fs.unlink(file.path, (unlinkErr) => {
                if (unlinkErr) console.error("Error deleting file after DB error:", unlinkErr);
            });
            res.status(500).json({ message: "Gagal upload file dan menyimpan data.", error: dbError.message });
        } finally {
            connection.release(); // Always release connection
        }
    });
});

// Route to get a list of sent documents (NOT DELETED)
app.get('/sent-list', authenticateToken, (req, res) => {
    const userEmail = req.user.email;
    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /sent-list route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }
    pool.getConnection((err, connection) => { // Use pool
        if (err) {
            console.error('Error getting database connection for sent-list:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }
        // MODIFIKASI QUERY: Lakukan JOIN dengan tabel 'users' untuk mendapatkan profile_picture
        const query = `
            SELECT 
                sd.id, 
                sd.file_name, 
                sd.division, 
                sd.receiver, 
                sd.comment, 
                sd.hash_sha256, 
                sd.sender_email, 
                sd.sent_date, 
                sd.deleted,
                sd.status, -- Pastikan status juga diambil
                u.profile_picture AS profilePicturePath -- Ambil jalur foto profil dari tabel users
            FROM 
                sent_documents sd
            JOIN 
                users u ON sd.sender_email = u.email
            WHERE 
                sd.sender_email = ? AND sd.deleted = 0 
            ORDER BY 
                sd.sent_date DESC;
        `;
        connection.query(query, [userEmail], (err, results) => { // Use connection.query
            connection.release();
            if (err) {
                console.error('Error fetching sent documents:', err);
                return res.status(500).json({ message: 'Failed to fetch sent documents.' });
            }
            res.json(results);
        });
    });
});

// Route to get a list of received documents (NOT DELETED)
app.get('/receive-list', authenticateToken, (req, res) => {
    const userEmail = req.user.email;

    console.log('/receive-list route: User email from token:', userEmail);

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /receive-list route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => { // Use pool
        if (err) {
            console.error('Error getting database connection for receive-list:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }
        // MODIFIKASI QUERY: Lakukan JOIN dengan tabel 'users' untuk mendapatkan profile_picture dan 'division' dari sent_documents
        const query = `
            SELECT 
                rd.id, 
                rd.file_name, 
                rd.sender_email, 
                rd.receiver_email, 
                rd.received_date, 
                rd.status, 
                rd.comment, 
                rd.hash_sha256, 
                rd.deleted,
                u.profile_picture AS profilePicturePath, -- Ambil jalur foto profil pengirim
                sd.division AS sender_division -- Ambil divisi dari sent_documents
            FROM 
                received_documents rd
            JOIN 
                users u ON rd.sender_email = u.email -- Join dengan tabel users untuk mendapatkan foto profil pengirim
            JOIN
                sent_documents sd ON rd.hash_sha256 = sd.hash_sha256 AND rd.sender_email = sd.sender_email -- Join dengan sent_documents untuk mendapatkan divisi pengirim
            WHERE 
                rd.receiver_email = ? AND rd.deleted = 0 
            ORDER BY 
                rd.received_date DESC;
        `;
        connection.query(query, [userEmail], (err, results) => { // Use connection.query
            connection.release();
            if (err) {
                console.error("Database Query Error in /receive-list:", err); // Debugging
                return res.status(500).json({ error: 'Internal server error: ' + err.message });
            }

            res.json(results);
        });
    });
});

// Route to change received document status to 'Read'
app.post('/mark-as-read/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    const userEmail = req.user.email; // Email of the logged-in user

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /mark-as-read route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for mark-as-read:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        // Ensure the document is owned by the logged-in user and its status is 'Sent'
        const query = `
            UPDATE received_documents 
            SET status = 'Read' 
            WHERE id = ? AND receiver_email = ? AND status = 'Sent'
        `;
        connection.query(query, [documentId, userEmail], (err, result) => {
            connection.release();
            if (err) {
                console.error('Error marking document as read:', err);
                return res.status(500).json({ message: 'Gagal mengubah status dokumen.', error: err.message });
            }

            if (result.affectedRows === 0) {
                // Document not found, not owned by user, or already read
                return res.status(404).json({ message: 'Dokumen tidak ditemukan atau sudah Read.' });
            }

            logActivity(userEmail, 'Mark as Read', { documentId: documentId });
            res.status(200).json({ message: 'Status dokumen berhasil diubah menjadi Read.' });
        });
    });
});


// Route to move sent document to trash (UPDATE deleted status)
app.post('/trash/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    const userEmail = req.user.email;

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /trash/:id route.');
      return res.status(500).json({ error: "Internal server error: Database pool not initialized." });
    }

    pool.getConnection((err, connection) => { // Use pool
      if (err) {
        console.error('Error getting database connection for trash (sent):', err);
        return res.status(500).json({ error: "Internal server error: Database connection failed." });
      }

      const checkFileQuery = "SELECT file_name FROM sent_documents WHERE id = ? AND sender_email = ?";
      connection.query(checkFileQuery, [documentId, userEmail], (err, fileResult) => {
          if (err) {
              connection.release();
              console.error("Error checking file for trash:", err);
              return res.status(500).json({ error: "Internal server error" });
          }
          if (fileResult.length === 0) {
              connection.release();
              return res.status(404).json({ error: "Document not found or not owned by user." });
          }
          const fileName = fileResult[0].file_name;

          const query = "UPDATE sent_documents SET deleted = 1, deleted_at = NOW() WHERE id = ?";
          connection.query(query, [documentId], (err, result) => {
              connection.release();
              if (err) {
                  console.error("Error moving to trash:", err);
                  return res.status(500).json({ error: "Internal server error: " + err.message });
              }
              if (result.affectedRows === 0) {
                  return res.status(404).json({ error: "Document not found or already in trash." });
              }

              logActivity(userEmail, 'Move to Trash (Sent)', { documentId: documentId, fileName: fileName });
              res.json({ message: "Document moved to trash successfully." });
          });
      });
    });
});

// Route to move received document to trash (UPDATE deleted status)
app.post('/receive-trash/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    const userEmail = req.user.email;

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /receive-trash/:id route.');
      return res.status(500).json({ error: "Internal server error: Database pool not initialized." });
    }

    pool.getConnection((err, connection) => { // Use pool
      if (err) {
        console.error('Error getting database connection for receive-trash:', err);
        return res.status(500).json({ error: "Internal server error: Database connection failed." });
      }

      const checkFileQuery = "SELECT file_name FROM received_documents WHERE id = ? AND receiver_email = ?";
      connection.query(checkFileQuery, [documentId, userEmail], (err, fileResult) => {
          if (err) {
              connection.release();
              console.error("Error checking received file for trash:", err);
              return res.status(500).json({ error: "Internal server error" });
          }
          if (fileResult.length === 0) {
              connection.release();
              return res.status(404).json({ error: "Received document not found or not for this user." });
          }
          const fileName = fileResult[0].file_name;

          const query = "UPDATE received_documents SET deleted = 1, deleted_at = NOW() WHERE id = ?";
          connection.query(query, [documentId], (err, result) => {
              connection.release();
              if (err) {
                  console.error("Error moving received document to trash:", err);
                  return res.status(500).json({ error: "Internal server error: " + err.message });
              }
              if (result.affectedRows === 0) {
                  return res.status(404).json({ error: "Received document not found or already in trash." });
              }

              logActivity(userEmail, 'Move to Trash (Received)', { documentId: documentId, fileName: fileName });
              res.json({ message: "Received document moved to trash successfully." });
          });
      });
    });
});

// Route to get a list of documents in trash (sent and received)
app.get('/trash-list', authenticateToken, (req, res) => {
    const userEmail = req.user.email;
    console.log('/trash-list route: User email from token:', userEmail);
    let trashData = {
        sent: [],
        received: []
    };

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /trash-list route.');
      return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => { // Use pool
      if (err) {
        console.error('Error getting database connection for trash-list:', err);
        return res.status(500).json({ message: 'Server error: Database connection failed.' });
      }

      // MODIFIKASI QUERY: Ambil profile_picture untuk dokumen yang dikirim
      const querySent = `
          SELECT 
              sd.id, 
              sd.file_name, 
              sd.receiver, 
              sd.sent_date, 
              sd.deleted_at, 
              'sent' as type,
              sd.sender_email, -- Pastikan sender_email diambil
              u.profile_picture AS profilePicturePath
          FROM 
              sent_documents sd
          JOIN
              users u ON sd.sender_email = u.email
          WHERE 
              sd.sender_email = ? AND sd.deleted = 1 
          ORDER BY 
              sd.deleted_at DESC
      `;
      // MODIFIKASI QUERY: Ambil profile_picture untuk dokumen yang diterima
      const queryReceived = `
          SELECT 
              rd.id, 
              rd.file_name, 
              rd.sender_email, -- Pastikan sender_email diambil (ini adalah author untuk received doc)
              rd.received_date, 
              rd.deleted_at, 
              'received' as type,
              u.profile_picture AS profilePicturePath
          FROM 
              received_documents rd
          JOIN
              users u ON rd.sender_email = u.email -- Join dengan sender_email untuk mendapatkan foto profil pengirim
          WHERE 
              rd.receiver_email = ? AND rd.deleted = 1 
          ORDER BY 
              rd.deleted_at DESC
      `;

      connection.query(querySent, [userEmail], (errSent, resultsSent) => {
          if (errSent) {
              connection.release();
              console.error('Error fetching sent trash documents:', errSent);
              return res.status(500).json({ message: 'Failed to fetch sent trash documents.' });
          }
          trashData.sent = resultsSent;

          // Continue with the second query after the first one completes
          connection.query(queryReceived, [userEmail], (errReceived, resultsReceived) => {
              connection.release(); // Release connection after both queries are complete
              if (errReceived) {
                  console.error('Error fetching received trash documents:', errReceived);
                  return res.status(500).json({ message: 'Failed to fetch received trash documents.' });
              }
              trashData.received = resultsReceived;
              res.json(trashData);
          });
      });
    });
});

app.post('/restore/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    const userEmail = req.user.email;

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /restore/:id route.');
      return res.status(500).json({ error: "Internal server error: Database pool not initialized." });
    }

    pool.getConnection((err, connection) => { // Use pool
      if (err) {
        console.error('Error getting database connection for restore (sent):', err);
        return res.status(500).json({ error: "Internal server error: Database connection failed." });
      }

      const checkFileQuery = "SELECT file_name FROM sent_documents WHERE id = ? AND sender_email = ?";
      connection.query(checkFileQuery, [documentId, userEmail], (err, fileResult) => {
          if (err) {
              connection.release();
              console.error("Error checking file for restore:", err);
              return res.status(500).json({ error: "Internal server error" });
          }
          if (fileResult.length === 0) {
              connection.release();
              return res.status(404).json({ error: "Document not found or not owned by user." });
          }
          const fileName = fileResult[0].file_name;

          const query = "UPDATE sent_documents SET deleted = 0, deleted_at = NULL WHERE id = ?";
          connection.query(query, [documentId], (err, result) => {
              connection.release();
              if (err) {
                  console.error("Error restoring document:", err);
                  return res.status(500).json({ error: "Internal server error: " + err.message });
              }
              if (result.affectedRows === 0) {
                  return res.status(404).json({ error: "Document not found or not in trash." });
              }

              logActivity(userEmail, 'Restore (Sent)', { documentId: documentId, fileName: fileName });
              res.json({ message: "Document restored successfully." });
          });
      });
    });
});

app.post('/restore-received/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    const userEmail = req.user.email;

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /restore-received/:id route.');
      return res.status(500).json({ error: "Internal server error: Database pool not initialized." });
    }

    pool.getConnection((err, connection) => { // Use pool
      if (err) {
        console.error('Error getting database connection for restore (received):', err);
        return res.status(500).json({ error: "Internal server error: Database connection failed." });
      }

      const checkFileQuery = "SELECT file_name FROM received_documents WHERE id = ? AND receiver_email = ?";
      connection.query(checkFileQuery, [documentId, userEmail], (err, fileResult) => {
          if (err) {
              connection.release();
              console.error("Error checking received file for restore:", err);
              return res.status(500).json({ error: "Internal server error" });
          }
          if (fileResult.length === 0) {
              connection.release();
              return res.status(404).json({ error: "Received document not found or not for this user." });
          }
          const fileName = fileResult[0].file_name;

          const query = "UPDATE received_documents SET deleted = 0, deleted_at = NULL WHERE id = ?";
          connection.query(query, [documentId], (err, result) => {
              connection.release();
              if (err) {
                  console.error("Error restoring received document:", err);
                  return res.status(500).json({ error: "Internal server error: " + err.message });
              }
              if (result.affectedRows === 0) {
                  return res.status(404).json({ error: "Received document not found." });
              }

              logActivity(userEmail, 'Restore (Received)', { documentId: documentId, fileName: fileName });
              res.json({ message: "Received document restored successfully." });
          });
      });
    });
});

app.delete('/delete-permanent/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    const userEmail = req.user.email;

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /delete-permanent/:id route.');
      return res.status(500).json({ error: "Internal server error: Database pool not initialized." });
    }

    pool.getConnection((err, connection) => { // Use pool
      if (err) {
        console.error('Error getting database connection for delete-permanent (sent):', err);
        return res.status(500).json({ error: "Internal server error: Database connection failed." });
      }

      const checkFileQuery = "SELECT file_name FROM sent_documents WHERE id = ? AND sender_email = ?";
      connection.query(checkFileQuery, [documentId, userEmail], (err, fileResult) => {
          if (err) {
              connection.release();
              console.error("Error checking file for permanent delete:", err);
              return res.status(500).json({ error: "Internal server error" });
          }
          if (fileResult.length === 0) {
              connection.release();
              return res.status(404).json({ error: "Document not found or not owned by user." });
          }
          const fileName = fileResult[0].file_name;

          const query = "DELETE FROM sent_documents WHERE id = ?";
          connection.query(query, [documentId], (err, result) => {
              connection.release();
              if (err) {
                  console.error("Error permanently deleting document:", err);
                  return res.status(500).json({ error: "Internal server error: " + err.message });
              }
              if (result.affectedRows === 0) {
                  return res.status(404).json({ error: "Document not found." });
              }

              const filePath = path.join(__dirname, 'uploads', fileName);
              fs.unlink(filePath, (unlinkErr) => {
                  if (unlinkErr) {
                      console.error("Error deleting physical file:", unlinkErr);
                  } else {
                      console.log(`Physical file ${fileName} deleted.`);
                  }
              });

              logActivity(userEmail, 'Delete Permanently (Sent)', { documentId: documentId, fileName: fileName });
              res.json({ message: "Document permanently deleted." });
          });
      });
    });
});

app.delete('/delete-permanent-received/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    const userEmail = req.user.email;

    if (typeof pool === 'undefined' || pool === null) {
      console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /delete-permanent-received/:id route.');
      return res.status(500).json({ error: "Internal server error: Database pool not initialized." });
    }

    pool.getConnection((err, connection) => { // Use pool
      if (err) {
        console.error('Error getting database connection for delete-permanent (received):', err);
        return res.status(500).json({ error: "Internal server error: Database connection failed." });
      }

      const checkFileQuery = "SELECT file_name FROM received_documents WHERE id = ? AND receiver_email = ?";
      connection.query(checkFileQuery, [documentId, userEmail], (err, fileResult) => {
          if (err) {
              connection.release();
              console.error("Error checking received file for permanent delete:", err);
              return res.status(500).json({ error: "Internal server error" });
          }
          if (fileResult.length === 0) {
              connection.release();
              return res.status(404).json({ error: "Received document not found or not for this user." });
          }
          const fileName = fileResult[0].file_name;

          const query = "DELETE FROM received_documents WHERE id = ?";
          connection.query(query, [documentId], (err, result) => {
              connection.release();
              if (err) {
                  console.error("Error permanently deleting received document:", err);
                  return res.status(500).json({ error: "Internal server error: " + err.message });
              }
              if (result.affectedRows === 0) {
                  return res.status(404).json({ error: "Received document not found." });
              }

              const filePath = path.join(__dirname, 'uploads', fileName);
              fs.unlink(filePath, (unlinkErr) => {
                  if (unlinkErr) {
                      console.error("Error deleting physical file:", unlinkErr);
                  } else {
                      console.log(`Physical file ${fileName} deleted.`);
                  }
              });

              logActivity(userEmail, 'Delete Permanently (Received)', { documentId: documentId, fileName: fileName });
              res.json({ message: "Received document permanently deleted." });
          });
      });
    });
});

// Route to download file
app.get('/download/:fileName', authenticateToken, (req, res) => { // AUTHENTICATION PROTECTED
    const fileName = req.params.fileName;
    const filePath = path.join(__dirname, 'uploads', fileName);

    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            console.error(`File not found for download: ${fileName}`, err);
            return res.status(404).json({ message: 'File not found.' });
        }
        res.download(filePath, fileName, (downloadErr) => {
            if (downloadErr) {
                console.error(`Error downloading file: ${fileName}`, downloadErr);
                if (!res.headersSent) {
                    res.status(500).json({ message: 'Error downloading file.' });
                }
            }
        });
    });
});

// Route to get user details by ID (requires authentication)
app.get("/users/:userId", authenticateToken, (req, res) => {
    const userId = req.params.userId;
    // Add a check to ensure the requesting user is the same user or an admin
    if (parseInt(userId) !== req.user.userId && req.user.role !== 'Administrator') { // Note userId data type
        return res.status(403).json({ message: "Anda tidak memiliki izin untuk melihat detail user ini." });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /users/:userId route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for user details:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }
        // Select full_name, division as well
        const sql = "SELECT id, employee_id, email, profile_picture, role, division, full_name FROM users WHERE id = ?"; 
        connection.query(sql, [userId], (err, results) => {
            connection.release();
            if (err) {
                console.error("Error fetching user details:", err);
                return res.status(500).json({ message: "Gagal mengambil detail user" });
            }
            if (results.length > 0) {
                res.json(results[0]);
            } else {
                res.status(404).json({ message: "User tidak ditemukan." });
            }
        });
    });
});

// Route to update profile picture (requires authentication)
app.post("/users/update-profile-picture/:userId", authenticateToken, upload.single("profilePicture"), (req, res) => {
    const userId = parseInt(req.params.userId);

    if (parseInt(userId) !== req.user.userId) {
        return res.status(403).json({ message: "Anda tidak memiliki izin untuk memperbarui foto profil user lain." });
    }

    if (!req.file) {
        return res.status(400).json({ message: "Tidak ada file yang diunggah." });
    }

    const profilePicturePath = '/uploads/' + req.file.filename;
    console.log("profilePicturePath:", profilePicturePath);

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /users/update-profile-picture route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for update profile picture:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        const sql = 'UPDATE users SET profile_picture = ? WHERE id = ?';
        connection.query(sql, [profilePicturePath, userId], (err, result) => {
            if (err) {
                connection.release();
                console.error('Error updating profile picture in database:', err);
                return res.status(500).json({ message: "Gagal memperbarui foto profil di database." });
            }

            // Select full_name, division as well to include in the new token
            const sqlSelect = "SELECT id, email, profile_picture, role, division, full_name FROM users WHERE id = ?";
            connection.query(sqlSelect, [userId], (errSelect, resultsSelect) => {
                connection.release();
                if (errSelect) {
                    console.error("Gagal mengambil data user setelah update foto:", errSelect);
                    return res.status(500).json({ message: "Gagal mengambil data user." });
                }

                if (resultsSelect.length === 0) {
                    return res.status(404).json({ message: "User tidak ditemukan." });
                }

                const user = resultsSelect[0];
                const payload = {
                    userId: user.id,
                    email: user.email,
                    username: user.email, // Still keep email for 'username' claim
                    profilePicture: user.profile_picture,
                    role: user.role,
                    division: user.division,
                    full_name: user.full_name // Include full_name in new token payload
                };
                const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

                res.json({ message: "Foto profil berhasil diperbarui.", token, profilePicturePath: user.profile_picture });
            });
        });
    });
});

// Route to update username (email) (requires authentication)
app.post("/users/update-username/:userId", authenticateToken, (req, res) => {
    const userId = parseInt(req.params.userId);
    const { username } = req.body; // 'username' here refers to the email address

    if (parseInt(userId) !== req.user.userId) {
        return res.status(403).json({ message: "Anda tidak memiliki izin untuk memperbarui email user lain." });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /users/update-username route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for update username (email):', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        const sql = "UPDATE users SET email = ? WHERE id = ?";
        connection.query(sql, [username, userId], (err, result) => {
            if (err) {
                connection.release();
                console.error("Error updating username (email):", err);
                return res.status(500).json({ message: "Gagal memperbarui email." });
            }

            // Select full_name, division as well to include in the new token
            const sqlSelect = "SELECT id, email, profile_picture, role, division, full_name FROM users WHERE id = ?";
            connection.query(sqlSelect, [userId], (errSelect, resultsSelect) => {
                connection.release();
                if (errSelect) {
                    console.error("Gagal mengambil data user setelah update email:", errSelect);
                    return res.status(500).json({ message: "Gagal mengambil data user." });
                }

                if (resultsSelect.length === 0) {
                    return res.status(404).json({ message: "User tidak ditemukan." });
                }

                const user = resultsSelect[0];
                const payload = {
                    userId: user.id,
                    email: user.email,
                    username: user.email, // Still keep email for 'username' claim
                    profilePicture: user.profile_picture,
                    role: user.role,
                    division: user.division,
                    full_name: user.full_name // Include full_name in new token payload
                };
                const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
                
                res.json({ message: "Email berhasil diperbarui.", token });
            });
        });
    });
});

// NEW ROUTE: Route to update full name (requires authentication)
app.post("/users/update-fullname/:userId", authenticateToken, (req, res) => {
    const userId = parseInt(req.params.userId);
    const { full_name } = req.body;

    if (parseInt(userId) !== req.user.userId) {
        return res.status(403).json({ message: "Anda tidak memiliki izin untuk memperbarui nama user lain." });
    }

    if (!full_name || full_name.trim() === '') {
        return res.status(400).json({ message: "Nama lengkap tidak boleh kosong." });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /users/update-fullname route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for update full name:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        const sql = "UPDATE users SET full_name = ? WHERE id = ?";
        connection.query(sql, [full_name, userId], (err, result) => {
            if (err) {
                connection.release();
                console.error("Error updating full name:", err);
                return res.status(500).json({ message: "Gagal memperbarui nama lengkap." });
            }

            // Select all relevant user data to generate a new token
            const sqlSelect = "SELECT id, email, profile_picture, role, division, full_name FROM users WHERE id = ?";
            connection.query(sqlSelect, [userId], (errSelect, resultsSelect) => {
                connection.release();
                if (errSelect) {
                    console.error("Gagal mengambil data user setelah update nama lengkap:", errSelect);
                    return res.status(500).json({ message: "Gagal mengambil data user." });
                }

                if (resultsSelect.length === 0) {
                    return res.status(404).json({ message: "User tidak ditemukan." });
                }

                const user = resultsSelect[0];
                const payload = {
                    userId: user.id,
                    email: user.email,
                    username: user.email, // Still keep email for 'username' claim
                    profilePicture: user.profile_picture,
                    role: user.role,
                    division: user.division,
                    full_name: user.full_name // Include updated full_name in new token payload
                };
                const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
                
                logActivity(user.email, 'Update Full Name', { newFullName: full_name });
                res.json({ message: "Nama lengkap berhasil diperbarui.", token });
            });
        });
    });
});


// Route to get activity log for the logged-in user (already exists)
app.get("/activity-log", authenticateToken, (req, res) => {
    const userEmail = req.user.email;
    const summary = req.query.summary === 'true'; // Check if the request is for a summary

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /activity-log route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
      if (err) {
        console.error('Error getting database connection for activity-log:', err);
        return res.status(500).json({ message: 'Server error: Database connection failed.' });
      }

      let sql;
      if (summary) {
          // For summary, we might not need profile picture, but for consistency, let's include it
          sql = `
              SELECT 
                  al.action, 
                  al.user_email, 
                  al.timestamp,
                  u.full_name,
                  u.profile_picture AS profilePicturePath
              FROM 
                  activity_log al
              JOIN 
                  users u ON al.user_email = u.email
              WHERE 
                  al.user_email = ? 
              ORDER BY 
                  al.timestamp DESC 
              LIMIT 5
          `;
      } else {
          // Get all details for the full activity log page
          // MODIFIED: JOIN with users table to get full_name and profile_picture
          sql = `
              SELECT 
                  al.id, 
                  al.user_email, 
                  al.action, 
                  al.details, 
                  al.timestamp,
                  u.full_name, -- Tambahkan full_name
                  u.profile_picture AS profilePicturePath -- Tambahkan profile_picture
              FROM 
                  activity_log al
              JOIN 
                  users u ON al.user_email = u.email
              WHERE 
                  al.user_email = ? 
              ORDER BY 
                  al.timestamp DESC
          `;
      }
      
      connection.query(sql, [userEmail], (err, results) => {
        connection.release();
        if (err) {
            console.error("Fetch activity log error:", err);
            return res.status(500).json({ message: "Gagal mengambil data activity log", error: err.message });
        }
        res.json(results.map(log => ({
            ...log,
            details: log.details ? JSON.parse(log.details) : null // Parse JSON details
        })));
      });
    });
});

// Route to record newly opened/downloaded documents
app.post('/record-opened-document', authenticateToken, (req, res) => {
    const { documentId, fileName, documentType, receiverEmail } = req.body; // Tambahkan receiverEmail
    const userEmail = req.user.email; // Email pengguna yang melakukan aksi (membuka/mengunduh)

    if (!documentId || !fileName || !documentType) {
        return res.status(400).json({ message: "Data dokumen tidak lengkap untuk pencatatan." });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /record-opened-document route.');
        return res.status(500).json({ message: "Server error: Database pool not initialized." });
    }

    pool.getConnection(async (err, connection) => {
        if (err) {
            console.error('Error getting database connection for record-opened-document:', err);
            return res.status(500).json({ message: "Server error: Database connection failed." });
        }

        try {
            // Check if this document already exists in the recently_opened_documents list for this user
            const checkRecentlyOpenedQuery = `
                SELECT id FROM recently_opened_documents 
                WHERE user_email = ? AND document_id = ? AND document_type = ?
            `;
            const [checkResults] = await connection.promise().query(checkRecentlyOpenedQuery, [userEmail, documentId, documentType]);

            if (checkResults.length > 0) {
                // Document already exists in recently_opened_documents, update timestamp
                const updateRecentlyOpenedQuery = `
                    UPDATE recently_opened_documents SET opened_at = NOW() 
                    WHERE id = ?
                `;
                await connection.promise().query(updateRecentlyOpenedQuery, [checkResults[0].id]);
                await logActivity(userEmail, 'Document Re-opened', { documentId, fileName, documentType });
            } else {
                // Document does not exist in recently_opened_documents, insert new
                const insertRecentlyOpenedQuery = `
                    INSERT INTO recently_opened_documents (user_email, document_id, file_name, document_type, opened_at)
                    VALUES (?, ?, ?, ?, NOW())
                `;
                await connection.promise().query(insertRecentlyOpenedQuery, [userEmail, documentId, fileName, documentType]);
                await logActivity(userEmail, 'Document Opened', { documentId, fileName, documentType });
            }

            // --- LOGIC BARU UNTUK MENGUBAH STATUS DOKUMEN TERKIRIM MENJADI 'Read' ---
            // Ini akan terjadi ketika penerima membuka/mengunduh dokumen yang DIKIRIMKAN KEPADANYA.
            // documentType 'received' di sini merujuk pada jenis dokumen dari perspektif penerima.
            // userEmail adalah email penerima yang sedang login.
            if (documentType === 'received') { 
                // Perbarui status di tabel received_documents milik penerima
                const updateReceivedDocumentStatusQuery = `
                    UPDATE received_documents 
                    SET status = 'Read' 
                    WHERE id = ? AND receiver_email = ? AND status = 'Sent'
                `;
                await connection.promise().query(updateReceivedDocumentStatusQuery, [documentId, userEmail]);
                console.log(`Status dokumen diterima (ID: ${documentId}) diubah menjadi 'Read' oleh ${userEmail}.`);

                // Sekarang, cari sent_document_id yang sesuai dari tabel received_documents
                const [receivedDocRow] = await connection.promise().query(
                    "SELECT hash_sha256, sender_email FROM received_documents WHERE id = ?",
                    [documentId]
                );

                if (receivedDocRow.length > 0) {
                    const hash_sha256 = receivedDocRow[0].hash_sha256;
                    const sender_email = receivedDocRow[0].sender_email;

                    // Perbarui status dokumen di tabel sent_documents yang sesuai
                    // Menggunakan hash_sha256 dan sender_email untuk memastikan dokumen yang benar
                    const updateSentDocumentStatusQuery = `
                        UPDATE sent_documents 
                        SET status = 'Read' 
                        WHERE hash_sha256 = ? AND sender_email = ? AND status = 'Sent'
                    `;
                    const [updateSentResult] = await connection.promise().query(updateSentDocumentStatusQuery, [hash_sha256, sender_email]);
                    
                    if (updateSentResult.affectedRows > 0) {
                        await logActivity(userEmail, 'Document Status Updated (Sent by Receiver)', { documentId, fileName, newStatus: 'Read', sender: sender_email });
                        console.log(`Status dokumen terkirim yang sesuai (hash: ${hash_sha256}) diubah menjadi 'Read'.`);
                    } else {
                        console.log(`Tidak ada dokumen terkirim yang perlu diperbarui untuk hash ${hash_sha256} atau sudah Read.`);
                    }
                }
            }
            // --- AKHIR LOGIC STATUS UPDATE ---

            res.status(200).json({ message: 'Catatan dokumen dibuka/diunduh berhasil diperbarui.' });

        } catch (dbError) {
            console.error('Error in record-opened-document:', dbError);
            res.status(500).json({ message: 'Gagal mencatat dokumen dibuka/diunduh.', error: dbError.message });
        } finally {
            connection.release();
        }
    });
});


// Route to get a list of recently opened documents for the dashboard
app.get('/dashboard-recently-opened', authenticateToken, (req, res) => {
    const userEmail = req.user.email;

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /dashboard-recently-opened route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for dashboard-recently-opened:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        const query = `
            SELECT file_name, document_type, opened_at 
            FROM recently_opened_documents 
            WHERE user_email = ? 
            ORDER BY opened_at DESC 
            LIMIT 5
        `; // Limit to 5 latest documents
        connection.query(query, [userEmail], (err, results) => {
            connection.release();
            if (err) {
                console.error('Error fetching recently opened documents:', err);
                return res.status(500).json({ message: 'Gagal mengambil dokumen yang baru dibuka.', error: err.message });
            }
            res.json(results);
        });
    });
});

// Route to get the count of sent documents
app.get('/sent-count', authenticateToken, (req, res) => {
    const userEmail = req.user.email;
    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /sent-count route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for sent-count:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }
        const query = "SELECT COUNT(*) AS total_sent FROM sent_documents WHERE sender_email = ? AND deleted = 0";
        connection.query(query, [userEmail], (err, results) => {
            connection.release();
            if (err) {
                console.error('Error fetching sent count:', err);
                return res.status(500).json({ message: 'Failed to fetch sent count.' });
            }
            res.json({ total_sent: results[0].total_sent });
        });
    });
});

// Route to get the count of received documents
app.get('/receive-count', authenticateToken, (req, res) => {
    const userEmail = req.user.email;
    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /receive-count route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for receive-count:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }
        const query = "SELECT COUNT(*) AS total_received FROM received_documents WHERE receiver_email = ? AND deleted = 0";
        connection.query(query, [userEmail], (err, results) => {
            connection.release();
            if (err) {
                console.error('Error fetching received count:', err);
                return res.status(500).json({ message: 'Failed to fetch received count.' });
            }
            res.json({ total_received: results[0].total_received });
        });
    });
});

// ====================================================================
// Admin Routes (Require 'Administrator' Role)
// ====================================================================

// Route to get all users (Admin only)
app.get('/admin/users', authenticateToken, authorizeAdmin, (req, res) => {
    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /admin/users route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for admin/users:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }
        // Do not fetch password, only relevant data
        const sql = "SELECT id, employee_id, email, role, profile_picture, division, full_name FROM users ORDER BY id ASC"; // Include full_name
        connection.query(sql, (err, results) => {
            connection.release();
            if (err) {
                console.error("Error fetching all users for admin:", err);
                return res.status(500).json({ message: "Gagal mengambil daftar pengguna.", error: err.message });
            }
            res.json(results);
        });
    });
});

// Route to update user role (Admin only)
app.put('/admin/users/:userId/role', authenticateToken, authorizeAdmin, (req, res) => {
    const userId = parseInt(req.params.userId); // Ensure userId is an integer
    const { role } = req.body;

    if (!role) {
        return res.status(400).json({ message: "Peran tidak boleh kosong." });
    }

    // List of valid roles that can be set by admin
    const validRoles = ['Administrator', 'Employee', 'Auditor']; 
    if (!validRoles.includes(role)) {
        return res.status(400).json({ message: "Peran tidak valid atau tidak diizinkan untuk diatur melalui admin panel." });
    }

    // Ensure admin does not try to change their own role
    if (userId === req.user.userId) {
        return res.status(403).json({ message: "Anda tidak dapat mengubah peran Anda sendiri." });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /admin/users/:userId/role route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for update user role:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        const sql = "UPDATE users SET role = ? WHERE id = ?";
        connection.query(sql, [role, userId], (err, result) => {
            connection.release();
            if (err) {
                console.error("Error updating user role:", err);
                return res.status(500).json({ message: "Gagal memperbarui peran pengguna.", error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: "Pengguna tidak ditemukan." });
            }
            logActivity(req.user.email, 'Update User Role', { targetUserId: userId, newRole: role });
            res.json({ message: "Peran pengguna berhasil diperbarui." });
        });
    });
});

// Route to delete user (Admin only)
app.delete('/admin/users/:userId', authenticateToken, authorizeAdmin, (req, res) => {
    const userId = parseInt(req.params.userId); // Ensure userId is an integer

    // Ensure admin does not try to delete their own account
    if (userId === req.user.userId) {
        return res.status(403).json({ message: "Anda tidak dapat menghapus akun Anda sendiri." });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /admin/users/:userId route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for delete user:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        const sql = "DELETE FROM users WHERE id = ?";
        connection.query(sql, [userId], (err, result) => {
            connection.release();
            if (err) {
                console.error("Error deleting user:", err);
                return res.status(500).json({ message: "Gagal menghapus pengguna.", error: err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: "Pengguna tidak ditemukan." });
            }
            logActivity(req.user.email, 'Delete User', { targetUserId: userId });
            res.json({ message: "Pengguna berhasil dihapus." });
        });
    });
});

// MODIFIED Route: Get activity logs for Admin (can be filtered by division, action, and sorted)
app.get('/admin/activity-logs', authenticateToken, authorizeAdmin, (req, res) => {
    const divisionFilter = req.query.division; // Get division filter parameter
    const actionFilter = req.query.action;     // Get action filter parameter
    const sortBy = req.query.sortBy || 'timestamp_desc'; // Default sort order

    console.log(`Admin requesting activity logs. Division Filter: "${divisionFilter || 'No filter'}", Action Filter: "${actionFilter || 'No filter'}", Sort By: "${sortBy}"`);

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /admin/activity-logs route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection for admin activity logs:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        let sql = `
            SELECT 
                al.id, 
                al.user_email, 
                al.action, 
                al.details, 
                al.timestamp,
                u.full_name,
                u.profile_picture AS profilePicturePath,
                u.division -- Include division from users table
            FROM 
                activity_log al
            JOIN 
                users u ON al.user_email = u.email
            WHERE 1=1
        `;
        const params = [];

        if (divisionFilter) {
            sql += " AND u.division = ?";
            params.push(divisionFilter);
        }
        if (actionFilter) {
            sql += " AND al.action = ?";
            params.push(actionFilter);
        }

        // Add sorting logic
        switch (sortBy) {
            case 'timestamp_asc':
                sql += " ORDER BY al.timestamp ASC";
                break;
            case 'action_asc':
                sql += " ORDER BY al.action ASC";
                break;
            case 'action_desc':
                sql += " ORDER BY al.action DESC";
                break;
            case 'user_asc':
                sql += " ORDER BY u.full_name ASC, u.email ASC"; // Sort by full_name then email
                break;
            case 'user_desc':
                sql += " ORDER BY u.full_name DESC, u.email DESC"; // Sort by full_name then email
                break;
            case 'timestamp_desc':
            default:
                sql += " ORDER BY al.timestamp DESC";
                break;
        }

        connection.query(sql, params, (err, results) => {
            connection.release();
            if (err) {
                console.error("Error fetching admin activity logs:", err);
                return res.status(500).json({ message: "Failed to retrieve activity logs.", error: err.message });
            }
            // Parse JSON details if available
            const parsedResults = results.map(log => ({
                ...log,
                details: log.details ? JSON.parse(log.details) : null
            }));
            res.json(parsedResults);
        });
    });
});

// NEW Route: For password reset (without token authentication, based on email only)
// IMPORTANT NOTE: In a production application, this route should be more secure
// by sending a reset token to the user's email and verifying it.
// This is a simplified implementation for demonstration purposes.
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ message: "Email dan password baru harus diisi." });
    }

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /reset-password route.');
        return res.status(500).json({ message: "Server error: Database pool not initialized." });
    }

    pool.getConnection(async (err, connection) => {
        if (err) {
            console.error('Error getting database connection for reset-password:', err);
            return res.status(500).json({ message: "Server error: Database connection failed." });
        }

        try {
            // Cek apakah email terdaftar
            const [userCheck] = await connection.promise().query("SELECT id FROM users WHERE email = ?", [email]);
            if (userCheck.length === 0) {
                connection.release();
                return res.status(404).json({ message: "Email tidak terdaftar." });
            }

            // Update password pengguna
            const userId = userCheck[0].id;
            const updateSql = "UPDATE users SET password = ? WHERE id = ?";
            const [result] = await connection.promise().query(updateSql, [newPassword, userId]);

            if (result.affectedRows === 0) {
                connection.release();
                return res.status(500).json({ message: "Gagal memperbarui password." });
            }

            logActivity(email, 'Password Reset', {}); // Log aktivitas reset password
            res.status(200).json({ message: "Password berhasil direset." });

        } catch (dbError) {
            console.error("Error resetting password:", dbError);
            res.status(500).json({ message: "Gagal mereset password.", error: dbError.message });
        } finally {
            connection.release();
        }
    });
});

// NEW ROUTE: Route to update sent document details (receiver, comment, division)
app.put('/update-sent-document/:id', authenticateToken, async (req, res) => {
    const documentId = req.params.id;
    const { receiver, comment, division } = req.body; // Include division
    const userEmail = req.user.email; // Email of the logged-in user (sender)

    if (typeof pool === 'undefined' || pool === null) {
        console.error('CRITICAL ERROR: Database pool is not initialized or accessible in /update-sent-document route.');
        return res.status(500).json({ message: 'Server error: Database pool not initialized.' });
    }

    if (!receiver || !division) { // Basic validation
        return res.status(400).json({ message: "Penerima dan Divisi tidak boleh kosong." });
    }

    pool.getConnection(async (err, connection) => {
        if (err) {
            console.error('Error getting database connection for update-sent-document:', err);
            return res.status(500).json({ message: 'Server error: Database connection failed.' });
        }

        try {
            // Check if the document exists and belongs to the sender
            const [checkResult] = await connection.promise().query(
                "SELECT id FROM sent_documents WHERE id = ? AND sender_email = ?",
                [documentId, userEmail]
            );

            if (checkResult.length === 0) {
                connection.release();
                return res.status(404).json({ message: "Dokumen tidak ditemukan atau Anda tidak memiliki izin untuk mengeditnya." });
            }

            const updateSql = `
                UPDATE sent_documents 
                SET receiver = ?, comment = ?, division = ? 
                WHERE id = ?
            `;
            const [updateResult] = await connection.promise().query(updateSql, [receiver, comment, division, documentId]);

            if (updateResult.affectedRows === 0) {
                connection.release();
                return res.status(500).json({ message: "Gagal memperbarui dokumen." });
            }

            logActivity(userEmail, 'Update Sent Document', { documentId, newReceiver: receiver, newComment: comment, newDivision: division });
            res.status(200).json({ message: "Dokumen berhasil diperbarui." });

        } catch (dbError) {
            console.error("Error updating sent document:", dbError);
            res.status(500).json({ message: "Gagal memperbarui dokumen.", error: dbError.message });
        } finally {
            connection.release();
        }
    });
});
