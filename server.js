/*********************************
 * IMPORTS
 *********************************/
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
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
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
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
      "INSERT INTO admins (username, password) VALUES (?, ?)",
      ["admin", defaultPassword]
    );
    console.log("✅ Default admin created (admin / 1234)");
  }
});

/*********************************
 * AUTH
 *********************************/
const JWT_SECRET = process.env.JWT_SECRET || "mySuperSecretKey123";

function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token" });

  const token = auth.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.admin = decoded;
    next();
  });
}

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
        return res.json({ success: false });
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
 * CSV IMPORT (BUSES)
 *********************************/
app.post(
  "/admin/import-buses",
  verifyAdmin,
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const rows = [];

    fs.createReadStream(req.file.path)
      .pipe(csv())
      .on("data", (row) => {
        if (!row.bus_number) return; // skip empty rows
        rows.push(row);
      })
      .on("end", () => {
        rows.forEach((b) => {
          db.run(
            `INSERT INTO buses
            (bus_number, route_from, route_to, departure_time, arrival_time, depot)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [
              b.bus_number,
              b.from,
              b.to,
              b.departure,
              b.arrival,
              b.depot
            ]
          );
        });

        res.json({ success: true, inserted: rows.length });
      });
  }
);

/*********************************
 * GET ALL UPLOADED BUSES (ADMIN)
 *********************************/
app.get("/admin/buses", verifyAdmin, (req, res) => {
  db.all("SELECT * FROM buses ORDER BY id DESC", [], (err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
  });
});

/*********************************
 * SERVER START
 *********************************/
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("✅ Backend running on port " + PORT);
});
