// src/server.js
"use strict";

/**
 * Backend AR Química - versión estable para Render
 * -------------------------------------------------
 * • Express + Socket.IO (live ranking)
 * • PostgreSQL remoto con SSL
 * • Compatible con JSON, x-www-form-urlencoded y text/plain
 * • Endpoints:
 *    GET  /scores/top?n=20
 *    POST /scores { name, score }
 */

const express = require("express");
const http = require("http");
const cors = require("cors");
const { Pool } = require("pg");
const { Server } = require("socket.io");

// ------------------------
// Configuración base
// ------------------------
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.warn("⚠️  DATABASE_URL no está definido. Probablemente estás en local.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

// ------------------------
// Middlewares
// ------------------------
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Permitir text/plain con JSON adentro (algunas SDK móviles)
app.use((req, _res, next) => {
  if (req.is("text/plain") && typeof req.body === "string") {
    try { req.body = JSON.parse(req.body); } catch { /* ignora si no es JSON */ }
  }
  next();
});

// ------------------------
// Helpers
// ------------------------
async function getTop(n = 20) {
  const limit = Math.max(1, Math.min(Number(n) || 20, 500));
  const { rows } = await pool.query(
    `SELECT id, name, score, created_at
       FROM scores
      ORDER BY score DESC, id ASC
      LIMIT $1`,
    [limit]
  );
  return rows;
}

// ------------------------
// Rutas HTTP
// ------------------------

// Health check y raíz
app.get("/", (_req, res) =>
  res.json({ ok: true, service: "ar-back", now: new Date().toISOString() })
);
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// Obtener top N
app.get("/scores/top", async (req, res) => {
  try {
    const n = Math.max(1, Math.min(parseInt(req.query.n || "20", 10) || 20, 500));
    const rows = await getTop(n);
    res.json(rows);
  } catch (err) {
    console.error("GET /scores/top error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

// Registrar nuevo puntaje
app.post("/scores", async (req, res) => {
  try {
    console.log("📩 POST /scores body:", req.body);

    let { name, score } = req.body || {};
    name = String(name || "").trim().slice(0, 80);
    score = Number(score);

    if (!name) return res.status(400).json({ error: "name_required" });
    if (!Number.isFinite(score)) return res.status(400).json({ error: "invalid_score" });

    await pool.query("INSERT INTO scores (name, score) VALUES ($1, $2)", [name, score]);

    const top20 = await getTop(20);
    io.emit("top_updated", top20);

    res.json({ ok: true });
  } catch (err) {
    console.error("POST /scores error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

// ------------------------
// Socket.IO (live updates)
// ------------------------
io.on("connection", (socket) => {
  console.log("🔌 Socket conectado:", socket.id);

  socket.on("disconnect", (reason) => {
    console.log("🔌 Socket desconectado:", socket.id, reason);
  });

  socket.on("get_top", async (n) => {
    try {
      const rows = await getTop(n || 20);
      socket.emit("top", rows);
    } catch (err) {
      console.error("get_top error:", err);
      socket.emit("top", []);
    }
  });
});

// ------------------------
// Inicio del servidor
// ------------------------
server.listen(PORT, () => {
  console.log(`✅ Servidor escuchando en http://0.0.0.0:${PORT}`);
});
