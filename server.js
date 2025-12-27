


function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const db = new sqlite3.Database("./bus.db");

const JWT_SECRET = "mySuperSecretKey123";
const axios = require("axios");


/* =========================
   Middleware
   ========================= */
app.use(cors());
app.use(express.json());

/* =========================
   Email setup
   ========================= */






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
/* =========================
   STATIONS API (100% SAFE)
   ========================= */
app.get("/stations", (req, res) => {
  db.all(
    "SELECT DISTINCT name FROM stations ORDER BY name",
    [],
    (err, rows) => {

      if (err) {
        console.error("❌ SQLite error:", err);
        return res.json([]);   // ❌ NEVER return 500
      }

      if (!Array.isArray(rows)) {
        return res.json([]);
      }

      const names = rows
        .map(r => r.name)
        .filter(Boolean);   // remove null / empty

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





// Get all routes
app.get("/admin/routes", verifyAdminToken, (req, res) => {
  db.all("SELECT * FROM routes", [], (err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
  });
});

// Get single route
app.get("/admin/route/:id", verifyAdminToken, (req, res) => {
  const id = req.params.id;

  db.get("SELECT * FROM routes WHERE id = ?", [id], (err, route) => {
    if (!route) return res.json(null);

    db.all(
      "SELECT name, time FROM stations WHERE route_id = ? ORDER BY id",
      [id],
      (err, stations) => {
        res.json({
          id: route.id,
          bus: route.bus,
          stations
        });
      }
    );
  });
});

// Add route
app.post("/admin/add-route", verifyAdminToken, (req, res) => {
  const { bus, stations } = req.body;

  if (!bus || !stations || stations.length < 2) {
    return res.json({ message: "Invalid data" });
  }

  db.run(
    "INSERT INTO routes (bus) VALUES (?)",
    [bus],
    function (err) {
      if (err) return res.json({ message: "DB error" });

      const routeId = this.lastID;
      const stmt = db.prepare(
        "INSERT INTO stations (route_id, name, time) VALUES (?, ?, ?)"
      );

      stations.forEach(s => {
        stmt.run(routeId, s.name, s.time);
      });

      stmt.finalize();
      res.json({ message: "Route added" });
    }
  );
});

// Update route
app.put("/admin/update-route/:id", verifyAdminToken, (req, res) => {
  const { bus, stations } = req.body;
  const id = req.params.id;

  if (!bus || !stations || stations.length < 2) {
    return res.json({ message: "Invalid data" });
  }

  db.run(
    "UPDATE routes SET bus = ? WHERE id = ?",
    [bus, id],
    () => {
      db.run("DELETE FROM stations WHERE route_id = ?", [id], () => {
        const stmt = db.prepare(
          "INSERT INTO stations (route_id, name, time) VALUES (?, ?, ?)"
        );

        stations.forEach(s => {
          stmt.run(id, s.name, s.time);
        });

        stmt.finalize();
        res.json({ message: "Route updated" });
      });
    }
  );
});

// Delete route
app.delete("/admin/delete-route/:id", verifyAdminToken, (req, res) => {
  const id = req.params.id;

  db.run("DELETE FROM stations WHERE route_id = ?", [id], () => {
    db.run("DELETE FROM routes WHERE id = ?", [id], () => {
      res.json({ message: "Route deleted" });
    });
  });
});

// Change password
app.post("/admin/change-password", verifyAdminToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;

  db.get(
    "SELECT * FROM admins WHERE id = ?",
    [req.admin.adminId],
    (err, admin) => {
      if (!admin) return res.json({ message: "Admin not found" });

      const ok = bcrypt.compareSync(oldPassword, admin.password);
      if (!ok) return res.json({ message: "Old password incorrect" });

      const hash = bcrypt.hashSync(newPassword, 10);
      db.run(
        "UPDATE admins SET password = ? WHERE id = ?",
        [hash, admin.id],
        () => res.json({ message: "Password changed successfully" })
      );
    }
  );
});



/* =========================
   FORGOT PASSWORD
   ========================= */
/* =========================
   FORGOT PASSWORD (WITH ERROR LOGGING)
   ========================= */
app.post("/admin/forgot-password", async (req, res) => {
  const { email } = req.body;

  // ✅ UI को तुरंत response
  res.json({ message: "If email exists, OTP will be sent shortly" });

  if (!email) return;

  db.get(
    "SELECT * FROM admins WHERE email = ?",
    [email],
    async (err, admin) => {
      if (err || !admin) return;

      const otp = generateOTP();
      const expiry = Date.now() + 10 * 60 * 1000;

      db.run(
        "UPDATE admins SET otp = ?, otp_expiry = ? WHERE id = ?",
        [otp, expiry, admin.id]
      );

      try {
        await axios.post(
          "https://api.brevo.com/v3/smtp/email",
          {
            sender: {
              name: "HR Route",
              email: "cosmosmatrixx@gmail.com" // ✔ verified sender
            },
            to: [{ email }],
            subject: "HR Route – Password Reset OTP",
            htmlContent: `
              <h2>Password Reset OTP</h2>
              <p>Your OTP is:</p>
              <h1>${otp}</h1>
              <p>This OTP is valid for 10 minutes.</p>
            `
          },
          {
            headers: {
              "api-key": process.env.BREVO_API_KEY, // 🔥 MOST IMPORTANT
              "Content-Type": "application/json"
            }
          }
        );

        console.log("✅ OTP email sent via Brevo API");
      } catch (e) {
        console.error(
          "❌ Brevo API error:",
          e.response?.data || e.message
        );
      }
    }
  );
});


/* =========================
   RESET PASSWORD
   ========================= */
app.post("/admin/reset-password", (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.json({ message: "All fields required" });
  }

  db.get(
    "SELECT * FROM admins WHERE email = ?",
    [email],
    (err, admin) => {
      if (!admin) return res.json({ message: "Invalid email" });

      if (admin.otp !== otp) {
        return res.json({ message: "Invalid OTP" });
      }

      if (Date.now() > admin.otp_expiry) {
        return res.json({ message: "OTP expired" });
      }

      const hash = bcrypt.hashSync(newPassword, 10);

      db.run(
        "UPDATE admins SET password = ?, otp = NULL, otp_expiry = NULL WHERE id = ?",
        [hash, admin.id],
        () => res.json({ message: "Password reset successful" })
      );
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
