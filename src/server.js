// src/server.js
// Backend AR Química — Express + Socket.IO + PostgreSQL (Render-ready)

const express = require("express");
const http = require("http");
const cors = require("cors");
const { Pool } = require("pg");

// ====== Config ======
const PORT = process.env.PORT || 10000;
const app = express();
const server = http.createServer(app);

// CORS: permite tu web (puedes agregar más orígenes si los necesitas)
const io = require("socket.io")(server, {
  cors: {
    origin: ["*"], // si quieres cerrarlo: ["https://TU-SITIO.netlify.app", "http://localhost:5500"]
    methods: ["GET", "POST"],
  },
});

app.use(cors({ origin: "*"}));
app.use(express.json());

// ====== PostgreSQL ======
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // En Render Postgres se requiere SSL
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Crea tabla si no existe
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scores (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      score INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS scores_score_idx ON scores(score DESC);
    CREATE INDEX IF NOT EXISTS scores_created_idx ON scores(created_at DESC);
  `);
}

// Helper para traer TOP N
async function getTop(n = 20) {
  const lim = Math.max(1, Math.min(Number(n) || 20, 500));
  const { rows } = await pool.query(
    `SELECT id, name, score, created_at
     FROM scores
     ORDER BY score DESC, name ASC
     LIMIT $1`,
    [lim]
  );
  return rows;
}

// ====== Rutas HTTP ======
app.get("/", (_req, res) => {
  res.json({ ok: true, service: "ar-back", version: 1 });
});

app.get("/health", (_req, res) => res.send("ok"));

app.get("/scores/top", async (req, res) => {
  try {
    const n = req.query.n || 20;
    const rows = await getTop(n);
    res.json(rows);
  } catch (err) {
    console.error("GET /scores/top error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

app.post("/scores", async (req, res) => {
  try {
    let { name, score } = req.body || {};
    name = String(name || "").trim().slice(0, 80);
    score = Number(score) || 0;

    if (!name) return res.status(400).json({ error: "name_required" });
    if (!Number.isFinite(score)) return res.status(400).json({ error: "invalid_score" });

    await pool.query(
      "INSERT INTO scores (name, score) VALUES ($1, $2)",
      [name, score]
    );

    // Notifica a todos los sockets que hay nuevo TOP
    const top = await getTop(20);
    io.emit("top_updated", top);

    res.json({ ok: true });
  } catch (err) {
    console.error("POST /scores error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

// ====== Socket.IO (tiempo real) ======
io.on("connection", (socket) => {
  console.log("🔌 Socket conectado:", socket.id);

  // Cliente pide el top inicial
  socket.on("get_top", async (n) => {
    try {
      const top = await getTop(n || 20);
      socket.emit("top", top);
    } catch (e) {
      console.error("socket get_top error:", e);
    }
  });

  socket.on("disconnect", (reason) => {
    console.log("🔌 Socket desconectado:", socket.id, reason);
  });
});

// ====== Start ======
(async () => {
  try {
    console.log("✅ Conectando a PostgreSQL remoto (Render)...");
    await ensureSchema();
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`);
    });
  } catch (e) {
    console.error("❌ Error al iniciar servidor:", e);
    process.exit(1);
  }
})();
