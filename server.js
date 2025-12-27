
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}


const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");




const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,          // ✅ IMPORTANT CHANGE
  secure: false,      // TLS
  auth: {
     user: "cosmosmatrixx@gmail.com",
    pass: "pqeedsmikpffqfgs"
  },
  tls: {
    rejectUnauthorized: false
  }
});


// transporter.sendMail({
//   from: "cosmosmatrixx@gmail.com",
//   to: "cosmosmatrixx@gmail.com",
//   subject: "Test Email",
//   text: "Email transporter is working successfully!"
// }, (err, info) => {
//   if (err) {
//     console.log("Email error:", err);
//   } else {
//     console.log("Email sent:", info.response);
//   }
// });





const JWT_SECRET = "mySuperSecretKey123"; 

function verifyAdminToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  // Format: Bearer TOKEN
  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Invalid token format" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Token invalid or expired" });
    }

    // Token valid → आगे जाने दो
    req.admin = decoded;
    next();
  });
}



const express = require("express");
const cors = require("cors");

const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./bus.db");

const app = express();

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
    password TEXT
  )
`);

// db.run(`ALTER TABLE admins ADD COLUMN email TEXT`);
// db.run(`ALTER TABLE admins ADD COLUMN otp TEXT`);
// db.run(`ALTER TABLE admins ADD COLUMN otp_expiry INTEGER`);

db.run(
  "UPDATE admins SET email = ? WHERE username = 'admin'",
  ["cosmosmatrixx@gmail.com"]
);


});


const defaultPassword = bcrypt.hashSync("1234", 10);

db.get("SELECT * FROM admins WHERE username = 'admin'", (err, row) => {
  if (!row) {
    db.run(
      "INSERT INTO admins (username, password) VALUES (?, ?)",
      ["admin", defaultPassword]
    );
    console.log("✅ Default admin created (username: admin, password: 1234)");
  }
});



app.use(cors());
app.use(express.json());





// Search API
app.get("/search", (req, res) => {
  const from = req.query.from.toLowerCase();
  const to = req.query.to.toLowerCase();

  // 1️⃣ सभी routes निकालो
  db.all("SELECT * FROM routes", [], (err, routes) => {
    if (err) {
      return res.json([]);
    }

    let finalResult = [];
    let pending = routes.length;

    if (pending === 0) {
      return res.json([]);
    }

    routes.forEach(route => {
      // 2️⃣ उस route के stations निकालो (order by id)
      db.all(
        "SELECT name, time FROM stations WHERE route_id = ? ORDER BY id",
        [route.id],
        (err, stations) => {
          pending--;

          if (!stations || stations.length === 0) {
            if (pending === 0) res.json(finalResult);
            return;
          }

          const names = stations.map(s => s.name.toLowerCase());

          if (
            names.includes(from) &&
            names.includes(to) &&
            names.indexOf(from) < names.indexOf(to)
          ) {
            finalResult.push({
              bus: route.bus,
              stations: stations
            });
          }

          if (pending === 0) {
            res.json(finalResult);
          }
        }
      );
    });
  });
});







app.post("/admin/add-route", verifyAdminToken,(req, res) => {
  const bus = req.body.bus;
  const stations = req.body.stations;

  if (!bus || !stations || stations.length < 2) {
    return res.json({ message: "Invalid data" });
  }

  // 1️⃣ Route table में insert
  db.run(
    "INSERT INTO routes (bus) VALUES (?)",
    [bus],
    function (err) {
      if (err) {
        console.log(err);
        return res.json({ message: "DB error while saving route" });
      }

      const routeId = this.lastID;

      // 2️⃣ Stations table में insert
      const stmt = db.prepare(
        "INSERT INTO stations (route_id, name, time) VALUES (?, ?, ?)"
      );

      stations.forEach(st => {
        stmt.run(routeId, st.name, st.time);
      });

      stmt.finalize();

      res.json({ message: "Route saved in database" });
    }
  );
});


app.get("/admin/routes", verifyAdminToken, (req, res) => {
  db.all("SELECT * FROM routes", [], (err, rows) => {
    if (err) {
      return res.json([]);
    }
    res.json(rows);
  });
});



app.delete("/admin/delete-route/:id", verifyAdminToken, (req, res) => {
  const id = req.params.id;

  db.run("DELETE FROM stations WHERE route_id = ?", [id], () => {
    db.run("DELETE FROM routes WHERE id = ?", [id], err => {
      if (err) {
        return res.json({ message: "Delete failed" });
      }
      res.json({ message: "Route deleted" });
    });
  });
});



app.get("/admin/route/:id", verifyAdminToken, (req, res) => {
  const id = req.params.id;

  db.get("SELECT * FROM routes WHERE id = ?", [id], (err, route) => {
    if (err || !route) {
      return res.json(null);
    }

    db.all(
      "SELECT name, time FROM stations WHERE route_id = ? ORDER BY id",
      [id],
      (err, stations) => {
        res.json({
          id: route.id,
          bus: route.bus,
          stations: stations
        });
      }
    );
  });
});



app.put("/admin/update-route/:id", verifyAdminToken, (req, res) => {
  const id = req.params.id;
  const { bus, stations } = req.body;

  if (!bus || !stations || stations.length < 2) {
    return res.json({ message: "Invalid data" });
  }

  // 1️⃣ Update bus name
  db.run(
    "UPDATE routes SET bus = ? WHERE id = ?",
    [bus, id],
    err => {
      if (err) {
        return res.json({ message: "Route update failed" });
      }

      // 2️⃣ Old stations delete
      db.run(
        "DELETE FROM stations WHERE route_id = ?",
        [id],
        () => {
          // 3️⃣ New stations insert
          const stmt = db.prepare(
            "INSERT INTO stations (route_id, name, time) VALUES (?, ?, ?)"
          );

          stations.forEach(s => {
            stmt.run(id, s.name, s.time);
          });

          stmt.finalize();

          res.json({ message: "Route updated successfully" });
        }
      );
    }
  );
});



app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  // 1️⃣ Admin DB से निकालो
  db.get(
    "SELECT * FROM admins WHERE username = ?",
    [username],
    (err, admin) => {
      if (err || !admin) {
        return res.json({
          success: false,
          message: "Invalid credentials"
        });
      }

      // 2️⃣ Password compare (bcrypt)
      const match = bcrypt.compareSync(password, admin.password);

      if (!match) {
        return res.json({
          success: false,
          message: "Invalid credentials"
        });
      }

      // 3️⃣ JWT generate
      const token = jwt.sign(
        {
          adminId: admin.id,
          role: "admin"
        },
        JWT_SECRET,
        { expiresIn: "2h" }
      );

      // 4️⃣ Success response
      res.json({
        success: true,
        token: token
      });
    }
  );
});




app.post("/admin/change-password", verifyAdminToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const adminId = req.admin.adminId;

  // 1️⃣ Basic validation
  if (!oldPassword || !newPassword) {
    return res.json({ message: "Missing fields" });
  }

  if (newPassword.length < 4) {
    return res.json({ message: "Password too short" });
  }

  // 2️⃣ Admin DB से निकालो
  db.get(
    "SELECT * FROM admins WHERE id = ?",
    [adminId],
    (err, admin) => {
      if (err || !admin) {
        return res.json({ message: "Admin not found" });
      }

      // 3️⃣ Old password verify
      const match = bcrypt.compareSync(oldPassword, admin.password);

      if (!match) {
        return res.json({ message: "Old password incorrect" });
      }

      // 4️⃣ New password hash
      const newHash = bcrypt.hashSync(newPassword, 10);

      // 5️⃣ Update DB
      db.run(
        "UPDATE admins SET password = ? WHERE id = ?",
        [newHash, adminId],
        err => {
          if (err) {
            return res.json({ message: "Password update failed" });
          }

          res.json({ message: "Password updated successfully" });
        }
      );
    }
  );
});



app.post("/admin/forgot-password", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.json({ message: "Email is required" });
  }

  // 1️⃣ Admin find by email
  db.get(
    "SELECT * FROM admins WHERE email = ?",
    [email],
    (err, admin) => {
      if (!admin) {
        return res.json({ message: "Email not registered" });
      }

      // 2️⃣ Generate OTP
      const otp = generateOTP();
      const expiry = Date.now() + 10 * 60 * 1000; // 10 minutes

      // 3️⃣ Save OTP in DB
      db.run(
        "UPDATE admins SET otp = ?, otp_expiry = ? WHERE id = ?",
        [otp, expiry, admin.id],
        err => {
          if (err) {
            return res.json({ message: "Failed to save OTP" });
          }

          // 4️⃣ Send OTP via email
          transporter.sendMail({
            from: "cosmosmatrixx@gmail.com",
            to: email,
            subject: "Bus App – Password Reset OTP",
            text: `Your OTP is ${otp}. It is valid for 10 minutes.`
          });

          res.json({ message: "OTP sent to email" });
        }
      );
    }
  );
});


app.post("/admin/reset-password", (req, res) => {
  const { email, otp, newPassword } = req.body;

  // 1️⃣ Basic validation
  if (!email || !otp || !newPassword) {
    return res.json({ message: "All fields are required" });
  }

  if (newPassword.length < 4) {
    return res.json({ message: "Password too short" });
  }

  // 2️⃣ Admin find by email
  db.get(
    "SELECT * FROM admins WHERE email = ?",
    [email],
    (err, admin) => {
      if (!admin) {
        return res.json({ message: "Invalid email" });
      }

      // 3️⃣ OTP check
      if (admin.otp !== otp) {
        return res.json({ message: "Invalid OTP" });
      }

      // 4️⃣ OTP expiry check
      if (Date.now() > admin.otp_expiry) {
        return res.json({ message: "OTP expired" });
      }

      // 5️⃣ New password hash
      const hashedPassword = bcrypt.hashSync(newPassword, 10);

      // 6️⃣ Password update + OTP clear
      db.run(
        "UPDATE admins SET password = ?, otp = NULL, otp_expiry = NULL WHERE id = ?",
        [hashedPassword, admin.id],
        err => {
          if (err) {
            return res.json({ message: "Password reset failed" });
          }

          res.json({ message: "Password reset successful" });
        }
      );
    }
  );
});



// GET all unique stations
app.get("/stations", async (req, res) => {
  try {
    const routes = await Route.find({});

    const stationSet = new Set();

    routes.forEach(route => {
      if (Array.isArray(route.stations)) {
        route.stations.forEach(s => {
          if (s && s.name) {
            stationSet.add(s.name.trim());
          }
        });
      }
    });

    res.json(Array.from(stationSet).sort());

  } catch (err) {
    console.error("Stations API error:", err);
    res.status(500).json({ error: "Failed to fetch stations" });
  }
});



// Server start
// app.listen(3000, () => {
//   console.log("Backend running on http://localhost:3000");
// });


const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Backend running on port " + PORT);
});


app.listen(3000, "0.0.0.0", () => {
  console.log("Backend running on all devices");
});