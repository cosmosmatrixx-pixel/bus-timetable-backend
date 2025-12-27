function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const app = express();
const db = new sqlite3.Database("./bus.db");

const JWT_SECRET = "mySuperSecretKey123";

/* =========================
   Middleware
   ========================= */
app.use(cors());
app.use(express.json());

/* =========================
   Email setup
   ========================= */
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "cosmosmatrixx@gmail.com",
    pass: "pqeedsmikpffqfgs"
  }
});

/* =========================
   Auth middleware
   ========================= */
function verifyAdminToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "No token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Invalid token" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token expired" });
    req.admin = decoded;
    next();
  });
}

/* =========================
   DB Tables
   ========================= */
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS routes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      bus TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS stations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      route_id INTEGER,
      name TEXT,
      time TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      email TEXT,
      otp TEXT,
      otp_expiry INTEGER
    )
  `);
});

/* =========================
   Default admin
   ========================= */
const defaultPassword = bcrypt.hashSync("1234", 10);

db.get("SELECT * FROM admins WHERE username = 'admin'", (err, row) => {
  if (!row) {
    db.run(
      "INSERT INTO admins (username, password, email) VALUES (?, ?, ?)",
      ["admin", defaultPassword, "cosmosmatrixx@gmail.com"]
    );
    console.log("✅ Default admin created");
  }
});

/* =========================
   SEARCH API
   ========================= */
app.get("/search", (req, res) => {
  const from = req.query.from.toLowerCase();
  const to = req.query.to.toLowerCase();

  db.all("SELECT * FROM routes", [], (err, routes) => {
    if (err) return res.json([]);

    let result = [];
    let pending = routes.length;

    if (pending === 0) return res.json([]);

    routes.forEach(route => {
      db.all(
        "SELECT name, time FROM stations WHERE route_id = ? ORDER BY id",
        [route.id],
        (err, stations) => {
          pending--;

          if (!stations || stations.length === 0) {
            if (pending === 0) res.json(result);
            return;
          }

          const names = stations.map(s => s.name.toLowerCase());

          if (
            names.includes(from) &&
            names.includes(to) &&
            names.indexOf(from) < names.indexOf(to)
          ) {
            result.push({ bus: route.bus, stations });
          }

          if (pending === 0) res.json(result);
        }
      );
    });
  });
});

/* =========================
   ⭐ STATIONS API (FIXED)
   ========================= */
app.get("/stations", (req, res) => {
  db.all(
    "SELECT DISTINCT name FROM stations ORDER BY name",
    [],
    (err, rows) => {
      if (err) {
        console.error("❌ Stations error:", err);
        return res.status(500).json([]);
      }

      const names = rows.map(r => r.name);
      res.json(names);
    }
  );
});

/* =========================
   ADMIN APIs
   ========================= */
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM admins WHERE username = ?",
    [username],
    (err, admin) => {
      if (!admin) {
        return res.json({ success: false });
      }

      const match = bcrypt.compareSync(password, admin.password);
      if (!match) return res.json({ success: false });

      const token = jwt.sign(
        { adminId: admin.id },
        JWT_SECRET,
        { expiresIn: "2h" }
      );

      res.json({ success: true, token });
    }
  );
});

/* =========================
   Server start (ONLY ONE)
   ========================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("✅ Backend running on port " + PORT);
});
