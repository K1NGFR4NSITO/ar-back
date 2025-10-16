// src/server.js
"use strict";

/**
 * Backend AR Química - Render
 * - Express + Socket.IO
 * - PostgreSQL (Render managed) con SSL
 * - Endpoints:
 *    GET  /scores/top?n=20
 *    POST /scores {name, score}
 * - Emite eventos Socket.IO:
 *    "top" (respuesta a "get_top")
 *    "top_updated" (cuando se inserta un score nuevo)
 *
 * Notas:
 *  - Acepta JSON y también x-www-form-urlencoded y text/plain (por si la app móvil no manda JSON estricto).
 *  - Se retiró el WS "puro" con 'ws' (causaba invalid close code en Render). Nos quedamos con Socket.IO.
 */

const express = require("express");
const http = require("http");
const cors = require("cors");
const morgan = require("morgan");
const { Pool } = require("pg");
const { Server } = require("socket.io");

// ------------------------
// Config / Setup
// ------------------------
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL; // Render la inyecta

if (!DATABASE_URL) {
  console.warn("⚠️  DATABASE_URL no está definido. ¿Estás corriendo en local?");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Requerido por Render PG
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

// Middlewares
app.use(cors({ origin: "*"}));
app.use(morgan("tiny"));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Si llega text/plain con JSON dentro (algunas SDKs móviles)
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

// Pequeño “wake” para Render (y health)
app.get("/", (_req, res) => res.json({ ok: true, service: "ar-back", now: new Date().toISOString() }));
app.get("/healthz", (_req, res) => res.json({ ok: true }));
app.get("/wake", (_req, res) => res.json({ ok: true, woke: new Date().toISOString() }));

// ------------------------
// API
// ------------------------

// TOP N
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

// INSERT SCORE (JSON o form-encoded)
app.post("/scores", async (req, res) => {
  try {
    // Log diagnóstico mínimo (no sensitivo)
    console.log("POST /scores body:", req.body);

    let { name, score } = req.body || {};
    name = String(name || "").trim().slice(0, 80);
    score = Number(score);

    if (!name) return res.status(400).json({ error: "name_required" });
    if (!Number.isFinite(score)) return res.status(400).json({ error: "invalid_score" });

    await pool.query(
      "INSERT INTO scores (name, score) VALUES ($1, $2)",
      [name, score]
    );

    // Actualiza a los clientes en vivo
    const top20 = await getTop(20);
    io.emit("top_updated", top20);

    res.json({ ok: true });
  } catch (err) {
    console.error("POST /scores error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

// ------------------------
// Socket.IO (live ranking)
// ------------------------
io.on("connection", (socket) => {
  console.log("🔌 socket conectado:", socket.id);

  socket.on("disconnect", (reason) => {
    console.log("🔌 socket desconectado:", socket.id, reason);
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
// WS "puro" con 'ws' (DESACTIVADO EN RENDER)
// ------------------------
/**
 * ATENCIÓN:
 * Los errores de:
 *  - WS_ERR_INVALID_CLOSE_CODE
 *  - RangeError: Invalid WebSocket frame: invalid status code XXXXX
 * venían del servidor WS crudo (paquete 'ws') corriendo en Render.
 * Para evitar los cierres / proxys intermedios, nos quedamos con Socket.IO.
 *
 * Si quieres usar WS puro sólo en local, podrías activarlo
 * condicionando por NODE_ENV === 'development'.
 */

// ------------------------
// Start
// ------------------------
server.listen(PORT, () => {
  console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`);
});
