/*********************************
 * IMPORTS
 *********************************/
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");

/*********************************
 * APP INIT
 *********************************/
const app = express();
app.use(cors());
app.use(express.json());

/*********************************
 * FILE UPLOAD
 *********************************/
const upload = multer({ dest: "uploads/" });

/*********************************
 * DATABASE
 *********************************/
const db = new sqlite3.Database("./bus.db");

/*********************************
 * TABLES
 *********************************/
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS buses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      bus_number TEXT,
      route_from TEXT,
      route_to TEXT,
      departure_time TEXT,
      arrival_time TEXT,
      depot TEXT
    )
  `);

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

/*********************************
 * DEFAULT ADMIN
 *********************************/
const defaultPassword = bcrypt.hashSync("1234", 10);

db.get("SELECT * FROM admins WHERE username='admin'", (err, row) => {
  if (!row) {
    db.run(
      "INSERT INTO admins (username, password, email) VALUES (?, ?, ?)",
      ["admin", defaultPassword, "cosmosmatrixx@gmail.com"]
    );
    console.log("✅ Default admin created (admin / 1234)");
  }
});

/*********************************
 * AUTH
 *********************************/
const JWT_SECRET = process.env.JWT_SECRET || "mySuperSecretKey123";

function verifyAdminToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Invalid token" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token expired" });
    req.admin = decoded;
    next();
  });
}

/*********************************
 * EMAIL (OTP)
 *********************************/
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "cosmosmatrixx@gmail.com",
    pass: "pqeedsmikpffqfgs"
  }
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/*********************************
 * CSV IMPORT (BUSES)
 *********************************/
app.post(
  "/admin/import-buses",
  verifyAdminToken,
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const buses = [];

    fs.createReadStream(req.file.path)
      .pipe(csv())
      .on("data", (row) => buses.push(row))
      .on("end", () => {
        buses.forEach((bus) => {
          db.run(
            `INSERT INTO buses 
             (bus_number, route_from, route_to, departure_time, arrival_time, depot)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
              bus.bus_number,
              bus.from,
              bus.to,
              bus.departure,
              bus.arrival,
              bus.depot,
            ]
          );
        });

        res.json({ success: true, inserted: buses.length });
      });
  }
);

/*********************************
 * SEARCH API
 *********************************/
app.get("/search", (req, res) => {
  const from = req.query.from?.toLowerCase();
  const to = req.query.to?.toLowerCase();

  if (!from || !to) return res.json([]);

  db.all("SELECT * FROM routes", [], (err, routes) => {
    if (err || routes.length === 0) return res.json([]);

    let result = [];
    let pending = routes.length;

    routes.forEach((route) => {
      db.all(
        "SELECT name, time FROM stations WHERE route_id=? ORDER BY id",
        [route.id],
        (err, stations) => {
          pending--;

          const names = stations.map((s) => s.name.toLowerCase());
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

/*********************************
 * ADMIN LOGIN
 *********************************/
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM admins WHERE username=?",
    [username],
    (err, admin) => {
      if (!admin || !bcrypt.compareSync(password, admin.password)) {
        return res.json({ success: false, message: "Invalid credentials" });
      }

      const token = jwt.sign(
        { adminId: admin.id },
        JWT_SECRET,
        { expiresIn: "2h" }
      );

      res.json({ success: true, token });
    }
  );
});

/*********************************
 * SERVER START (IMPORTANT)
 *********************************/
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("✅ Backend running on port " + PORT);
});
