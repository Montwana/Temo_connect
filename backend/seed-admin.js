import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import pkg from "pg";
dotenv.config();
const { Pool } = pkg;

const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
});

const run = async () => {
  const name = "Admin";
  const email = "admin@temo.local";
  const password = "Admin@123";
  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    `INSERT INTO users (name, email, password_hash, role, status)
     VALUES ($1,$2,$3,'admin','approved')
     ON CONFLICT (email) DO NOTHING`,
    [name, email, hash]
  );
  console.log("Admin seeded:", email, "password:", password);
  process.exit(0);
};

run().catch((e) => { console.error(e); process.exit(1); });
