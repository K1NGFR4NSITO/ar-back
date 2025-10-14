// src/db.js
import pg from "pg";
import "dotenv/config";

const { Pool } = pg;

let pool;

// Si hay DATABASE_URL (Render/Railway), úsala con SSL
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
} else {
  // Modo local con variables separadas (tu .env actual)
  pool = new Pool({
    host: process.env.PGHOST || "localhost",
    port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
    database: process.env.PGDATABASE || "archem",
    user: process.env.PGUSER || "postgres",
    password: process.env.PGPASSWORD || "",
  });
}

export { pool };
