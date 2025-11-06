import express from "express";
import pkg from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import validator from "validator";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import multer from "multer";
import path from "path";

dotenv.config();
const { Pool } = pkg;
const JWT_SECRET = process.env.JWT_SECRET
const app = express();
app.use(express.json());

// --- Upload Image preparations ----
// Konfigurasi penyimpanan utk image profile
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // folder to save images
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + ext);
  },
});

// Filter file — hanya izinkan gambar
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("File harus berupa gambar (jpg/png)!"), false);
  }
};

// Batasi ukuran file (misalnya max 2MB)
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 2 * 1024 * 1024 } // 2 MB
}).single("file"); // field di postman = file

// --- upload image preparation end ----



// Koneksi ke PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    host: process.env.PGHOST,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    port: process.env.PGPORT,
    ssl: { rejectUnauthorized: false }
});

// Tes koneksi database
pool.connect()
    .then(() => console.log("Connected to PostgreSQL"))
    .catch(err => console.error("Database connection error:", err));


// --- the end points ----
// Mengambil list banner
app.get("/banner", async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM tbl_banner");
        res.json({
            status: 0,
            message: "Sukses",
            data:result.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

// registration 
app.post("/registration", async (req, res) => {
    try {
        const { email, password, first_name, last_name } = req.body;

        // validasi input
        if (!email || !password || !first_name || !last_name) {
            return res.status(400).json({
                status: 201,
                message: "Ada parameter yang kurang",
                data: {}
            });
        }

        // validasi email
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                status: 102,
                message: "Parameter email tidak sesuai format",
                data: {}
            });
        }

        // validasi password
        if (password.length < 8) {
            return res.status(400).json({
                status: 202,
                message: "Password harus lebih dari 8 karakter",
                data: {}
            });
        }

        // Check if email already exists
        const checkEmail = await pool.query("SELECT * FROM tbl_user WHERE email = $1", [email]);
        if (checkEmail.rows.length > 0) {
            return res.status(400).json({
                status: 203,
                message: "Email sudah terdaftar",
                data: {}
            });
        }

        // Hash password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user data to database
        const result = await pool.query(
            `INSERT INTO tbl_user 
             (email, password, first_name, last_name, modified_by, modified_date)
             VALUES ($1, $2, $3, $4, 'system', now())`,
            [email, hashedPassword, first_name, last_name]
        );

        res.json({
            status: 0,
            message: "Registrasi berhasil, silahkan login",
            data: {}
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

// --- LOGIN API ---
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if fields are filled
        if (!email || !password) {
            return res.status(400).json({
                status: 201,
                message: "Ada parameter yang kurang",
                data: {}
            });
        }

        // validasi email
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                status: 102,
                message: "Parameter email tidak sesuai format",
                data: {}
            });
        }

        // Check if user exists
        const userResult = await pool.query("SELECT * FROM tbl_user WHERE email = $1", [email]);
        if (userResult.rows.length === 0) {
            return res.status(401).json({ 
                status: 103, 
                message: "Username atau password salah",
                data: {}
            });
        }

        const user = userResult.rows[0];

        // Compare password (hashed)
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ 
                status: 103, 
                message: "Username atau password salah",
                data: {}
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.user_id, 
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                profile_image: user.profile_image
            },    
            JWT_SECRET,
            { expiresIn: "12h" }    // token valid for 12 hour
        );

        // Login success
        res.json({
            status: 0,
            message: "Login sukses",
            data: {
                token: token
            },
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

// -- Protected Routes --
app.get("/profile", verifyToken, async (req, res) => {
    try {
    // Check get the user data
    const userResult = await pool.query("SELECT * FROM tbl_user WHERE user_id = $1", [req.user.id]);
    if (userResult.rows.length === 0) {
        return res.status(401).json({ 
            status: 204, 
            message: "Profile tidak ditemukan",
            data: {}
        });
    }

    const user = userResult.rows[0];
    res.json({
        status: 0,
        message: "Sukses",
        data: {
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            profile_image: user.profile_image
        }
    });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

// update profile
app.put("/profile/update", verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { first_name, last_name } = req.body;

        // validation input
        if (!first_name || !last_name) {
            return res.status(400).json({
                status: 201,
                message: "Ada parameter yang kurang",
            });
        }

        // update in database
        const result = await pool.query(
            "UPDATE tbl_user SET first_name=$1, last_name=$2 WHERE user_id=$3 RETURNING email, first_name, last_name, profile_image",
            [first_name, last_name, userId]
        );

        res.json({
            status: 0,
            message: "Update Pofile berhasil",
            data: result.rows[0],
        });
        } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

app.put("/profile/image", verifyToken, (req, res) => {
    upload(req, res, async (err) => {
        try {
            // cek jika upload gagal
            if (err instanceof multer.MulterError) {
                return res.status(400).json({ status: 205, message: "Upload gagal: " + err.message });
            } else if (err) {
                return res.status(400).json({ status: 100, message: err.message });
            }

            // Cek apakah file dikirim
            if (!req.file) {
                return res.status(400).json({ status: 206, message: "Tidak ada file yang diupload" });
            }

            const userId = req.user.id;
            const imagePath = req.file.path;

            // update user's profile image in database
            await pool.query(
                "UPDATE tbl_user SET profile_image = $1 WHERE user_id = $2",
                [imagePath, userId]
            );

            res.json({
                status: 0,
                message: "Update Profile Image berhasil",
                data: {
                    email: req.user.email,
                    first_name: req.user.first_name,
                    last_name: req.user.last_name,
                    profile_image: imagePath
                }
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ status: 100, message: err.message });
        }
    })
});

app.get("/balance", verifyToken, async (req, res) => {
    try {
        // Check get the user balance
        const balanceResult = await pool.query("SELECT * FROM tbl_balance WHERE user_id = $1", [req.user.id]);
        if (balanceResult.rows.length === 0) {
           return res.json({
                status: 0,
                message: "Get Balance Berhasil",
                data: {
                    balance: 0
                }
            });
        }

        const balance = balanceResult.rows[0];
        res.json({
            status: 0,
            message: "Get Balance Berhasil",
            data: {
                balance: balance.balance_value
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

app.post("/topup", verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { top_up_amount } = req.body;

        // Validasi input
        if (!top_up_amount || isNaN(top_up_amount) || top_up_amount <= 0) {
            return res.status(400).json({
                status: "102",
                message: "Paramter amount hanya boleh angka dan tidak boleh lebih kecil dari 0",
            });
        }

        // Ambil saldo lama
        let currentBalance = 0;
        const userResult = await pool.query("SELECT balance_value FROM tbl_balance WHERE user_id = $1", [userId]);
        if (userResult.rows.length !== 0) {
            currentBalance = userResult.rows[0].balance_value;
        } else { 
            // jika belum ada bbalance nya maka dibuat terlebih dahulu
            const insertResult = await pool.query(
            `INSERT INTO tbl_balance 
            (user_id, balance_value, modified_by, modified_date)
             VALUES ($1, 0, 'system', now())`,
            [userId]
            
        );
        }
        const newBalance = parseInt(currentBalance) + parseInt(top_up_amount);

        // Start database transaction
        await pool.query("BEGIN");
        
        // Update saldo di database
        const updateResult = await pool.query(
            "UPDATE tbl_balance SET balance_value = $1 WHERE user_id = $2 RETURNING user_id, balance_id, balance_value",
            [newBalance, userId]
        );

        const invNumber = generateInvoiceNumber();
        const balanceId = updateResult.rows[0].balance_id;
        // Insert into transaction history
        const insertHistory = await pool.query(
            `INSERT INTO tbl_trx_history (balance_id, invoice_number, amount, balance_before, balance_after, trx_type, description, created_by, created_date)
            VALUES ($1, $2, $3, $4, $5, 'TOPUP', 'Top Up Balance', 'system', now())
            RETURNING balance_id, invoice_number, amount, balance_after, created_date`,
            [balanceId, invNumber, top_up_amount, currentBalance, newBalance]
        );

        // Commit transaction
        await pool.query("COMMIT");

        res.json({
            status: 0,
            message: "Topup berhasil",
            data: {
                balance: newBalance,
            },
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

app.post("/transaction", verifyToken, async (req, res) => {
    try {
        const { service_code } = req.body;
        const userId = req.user.id;

        // validasi input
        if (!service_code) {
            return res.status(400).json({
                status: 201,
                message: "Ada parameter yang kurang",
                data: {}
            });
        }

        // get balance
        const balanceRes = await pool.query(
              "SELECT balance_id, balance_value FROM tbl_balance WHERE user_id = $1",
              [userId]
        );
        if (balanceRes.rows.length === 0)
            return res.status(404).json({ status: 206, message: "Belum ada saldo" });

        const { balance_id, balance_value } = balanceRes.rows[0];

        // get service
        const serviceRes = await pool.query(
              "SELECT service_name, service_tariff FROM tbl_service WHERE service_code = $1",
              [service_code]
        );
        if (serviceRes.rows.length === 0)
            return res.status(404).json({ status: 207, message: "Service tidak terdaftar" });
        const { service_name, service_tariff } = serviceRes.rows[0];

        if (balance_value < service_tariff)
            return res.status(400).json({ status: 208, message: "Saldo tidak cukup" });

        // Start database transaction
        await pool.query("BEGIN");

        // deduct balance
        const newBalance = balance_value - service_tariff;
        await pool.query(
              "UPDATE tbl_balance SET balance_value = $1 WHERE balance_id = $2",
              [newBalance, balance_id]
        );

        // create transaction history
        const invNumber = generateInvoiceNumber();
        const trx = await pool.query(
              `INSERT INTO tbl_trx_history 
               (balance_id, invoice_number, amount, balance_before, balance_after, trx_type, description, created_by, created_date)
               VALUES ($1, $2, $3, $4, $5, 'PAYMENT', $6, 'system', now())
               RETURNING *`,
              [balance_id, invNumber, service_tariff, balance_value, newBalance, service_name ]
        );

        // Commit transaction
        await pool.query("COMMIT");

        res.json({
              message: "Transaksi berhasil",
              data: {
                    invoice_number: invNumber,
                    service_code: service_code,
                    service_name: service_name,
                    transaction_type: "PAYMENT",
                    total_amount: service_tariff,
                    created_on: trx.rows[0].created_date
              }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/transaction/history", verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // Optional query params: offset & limit
        const offset = req.query.offset ? parseInt(req.query.offset) : null;
        const limit = req.query.limit ? parseInt(req.query.limit) : null;

        let query = `
            SELECT 
            trx.invoice_number,
            trx.trx_type as transaction_type,
            trx.description,
            trx.amount as total_amount,
            trx.created_date as created_on
            FROM tbl_trx_history as trx
            left JOIN tbl_balance as balance on trx.balance_id = balance.balance_id
            left JOIN tbl_user as usr on usr.user_id = balance.user_id
            WHERE usr.user_id = $1
            ORDER BY created_date DESC
        `;

        let params = [userId];

        // Add pagination 
        if (limit !== null && offset !== null) {
            query += ` LIMIT $2 OFFSET $3`;
            params.push(limit, offset);
        }

        const result = await pool.query(query, params);

        if (result.rows.length === 0)
            return res.status(404).json({ status: 208, message: "Belum ada transaksi" });

        res.json({
            status: 0,
            message: "Get History berhasil",
            data: result.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});

// Mengambil list service
app.get("/services", verifyToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM tbl_service");
        res.json({
            status: 0,
            message: "Sukses",
            data:result.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 100, message: err.message });
    }
});


// Jalankan server
app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});


// --- FUNCTIONS ----
function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({
        status:108,
        message: "Token tidak tidak valid atau kadaluwarsa",
        data: {}
    });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err ) return res.status(403).json({ 
            status:108,
            message: "Token tidak tidak valid atau kadaluwarsa",
            data: {}
        });
        req.user = user;
        next();
    });
}

// Generate invoice number
function generateInvoiceNumber() {
  const now = new Date();
  const dd = now.getDate().toString().padStart(2, "0");
  const mm = (now.getMonth() + 1).toString().padStart(2, "0");
  const yyyy = now.getFullYear().toString();
  const hh = now.getHours().toString().padStart(2, "0");
  const min = now.getMinutes().toString().padStart(2, "0");
  const sec = now.getSeconds().toString().padStart(2, "0");

  const dateTimePart = `${yyyy}${mm}${dd}${hh}${min}${sec}`;
  const randomPart = crypto.randomBytes(2).toString("hex").toUpperCase(); // contoh: A4F2

  return `INV${dateTimePart}-${randomPart}`; // contoh: INV20251105153428-A4F2
}