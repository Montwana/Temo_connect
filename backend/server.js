import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const app = express();

import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve all frontend files
app.use(express.static(path.join(__dirname, "../frontend")));



// CORS + JSON
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json());


// Postgres pool
const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
});

// Helpers
const signToken = (user) =>
  jwt.sign(
    { id: user.id, role: user.role, status: user.status, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES || "7d" }
  );

const auth = (req, res, next) => {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
};

const requireApprovedFarmer = (req, res, next) => {
  if (req.user.role !== "farmer") return res.status(403).json({ error: "Farmer only" });
  if (req.user.status !== "approved") {
    return res.status(403).json({ error: "Farmer not approved by admin yet" });
  }
  next();
};

// Health check
app.get("/", (req, res) => {
  res.json({ ok: true, message: "Temo Connect API running" });
});

/**
 * AUTH
 */

// Register (role: 'consumer' or 'farmer')
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "Missing fields" });
    }
    if (!["consumer", "farmer"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const { rows: existing } = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (existing.length) return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const status = role === "farmer" ? "pending" : "approved";

    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, status)
       VALUES ($1,$2,$3,$4,$5) RETURNING id, name, email, role, status`,
      [name, email, hash, role, status]
    );

    const token = signToken(rows[0]);
    res.status(201).json({ user: rows[0], token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!rows.length) return res.status(401).json({ error: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    // Note: Farmers can log in even if pending; posting is restricted until approved
    const { password_hash, ...safe } = user;
    const token = signToken(user);
    res.json({ user: safe, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});



/**
 * PRODUCTS
 */

// Public: list products from approved farmers
app.get("/api/products", async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT p.id, p.name, p.price, p.quantity, p.image_url, p.description,
              u.name AS farmer_name
       FROM products p
       JOIN users u ON u.id = p.farmer_id
       WHERE u.role='farmer' AND u.status='approved'
       ORDER BY p.created_at DESC`
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Farmer (approved) creates a product
app.post("/api/products", auth, requireApprovedFarmer, async (req, res) => {
  try {
    const { name, price, quantity, image_url, description } = req.body;
    if (!name || !price || !quantity) {
      return res.status(400).json({ error: "name, price, quantity are required" });
    }
    const { rows } = await pool.query(
      `INSERT INTO products (farmer_id, name, price, quantity, image_url, description)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.user.id, name, price, quantity, image_url || null, description || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Farmer updates own product
app.put("/api/products/:id", auth, requireApprovedFarmer, async (req, res) => {
  try {
    const { id } = req.params;
    // Ensure ownership
    const { rows: ownerCheck } = await pool.query(
      "SELECT id FROM products WHERE id=$1 AND farmer_id=$2",
      [id, req.user.id]
    );
    if (!ownerCheck.length) return res.status(404).json({ error: "Product not found" });

    const { name, price, quantity, image_url, description } = req.body;
    const { rows } = await pool.query(
      `UPDATE products
       SET name = COALESCE($1,name),
           price = COALESCE($2,price),
           quantity = COALESCE($3,quantity),
           image_url = COALESCE($4,image_url),
           description = COALESCE($5,description)
       WHERE id=$6
       RETURNING *`,
      [name, price, quantity, image_url, description, id]
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Farmer deletes own product
app.delete("/api/products/:id", auth, requireApprovedFarmer, async (req, res) => {
  try {
    const { id } = req.params;
    const { rowCount } = await pool.query(
      "DELETE FROM products WHERE id=$1 AND farmer_id=$2",
      [id, req.user.id]
    );
    if (!rowCount) return res.status(404).json({ error: "Product not found" });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * ADMIN
 * Approve pending farmers. (Requires an admin account.)
 */
app.get("/api/admin/farmers/pending", auth, requireRole("admin"), async (_req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, name, email, role, status, created_at FROM users WHERE role='farmer' AND status='pending' ORDER BY created_at ASC"
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.patch("/api/admin/farmers/:id/approve", auth, requireRole("admin"), async (req, res) => {
  try {
    const { id } = req.params;
    const { rowCount } = await pool.query(
      "UPDATE users SET status='approved' WHERE id=$1 AND role='farmer'",
      [id]
    );
    if (!rowCount) return res.status(404).json({ error: "Farmer not found or already approved" });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));

/*frontend*/

