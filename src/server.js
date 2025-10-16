// src/server.js
import express from "express";
import cors from "cors";
import "dotenv/config";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import { WebSocketServer } from "ws";
import { z } from "zod";
import { pool } from "./db.js";

const app = express();
app.use(cors({ origin: "*" })); // en prod: restringe a tu dominio/front
app.use(express.json());

// --- Health check (Render) ---
app.get("/health", (_req, res) => res.status(200).send("ok"));

// --- REST (fallback / pruebas) ---
const SubmitSchema = z.object({
  name: z.string().min(1).max(60),
  score: z.number().int().nonnegative(),
});

app.post("/scores", async (req, res) => {
  try {
    const data = SubmitSchema.parse(req.body);
    const { rows } = await pool.query(
      "insert into scores(name, score) values ($1,$2) returning id, name, score, created_at",
      [data.name, data.score]
    );
    await broadcastTop();
    res.json({ ok: true, score: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(400).json({ ok: false, error: String(err) });
  }
});

app.get("/scores/top", async (req, res) => {
  const n = Math.min(Math.max(parseInt(req.query.n ?? "10", 10) || 10, 1), 200);
  const { rows } = await pool.query(
    "select id, name, score, created_at from scores order by score desc, id asc limit $1",
    [n]
  );
  res.json(rows);
});

// --- HTTP base ---
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const server = http.createServer(app);

// --- Socket.IO (para web) ---
const io = new SocketIOServer(server, { cors: { origin: "*" } }); // prod: restringe

io.on("connection", (socket) => {
  console.log("✅ socket conectado:", socket.id);

  socket.on("get_top", async (n = 10) => {
    const top = await getTop(n);
    socket.emit("top", top);
  });

  socket.on("submit_score", async (payload, cb) => {
    try {
      const data = SubmitSchema.parse(payload);
      const { rows } = await pool.query(
        "insert into scores(name, score) values ($1,$2) returning id, name, score, created_at",
        [data.name, data.score]
      );
      cb?.({ ok: true, score: rows[0] });
      await broadcastTop();
    } catch (err) {
      console.error("submit_score error:", err);
      cb?.({ ok: false, error: String(err) });
    }
  });

  socket.on("disconnect", (reason) => {
    console.log("❌ socket desconectado:", socket.id, reason);
  });
});

// --- WebSocket puro (Unity) ---
// Acepta UPGRADE solo en /ws (evita que Render/health check rompa el WS)
const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false });

server.on("upgrade", (req, socket, head) => {
  try {
    const { pathname } = new URL(req.url, `http://${req.headers.host}`);
    if (pathname !== "/ws") {
      socket.destroy(); // cualquier cosa que no sea /ws se rechaza
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  } catch {
    socket.destroy();
  }
});

// Heartbeat para no cortar conexiones inactivas
function startHeartbeat(ws) {
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });
}
const pingInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, 30000);

wss.on("connection", (ws, req) => {
  console.log("✅ WS puro conectado:", req.socket.remoteAddress);
  startHeartbeat(ws);

  ws.on("error", (e) => console.warn("WS client error:", e?.message || e));

  ws.on("message", async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());

      if (msg?.type === "score") {
        const data = SubmitSchema.parse({ name: msg.name, score: msg.score });
        const { rows } = await pool.query(
          "insert into scores(name, score) values ($1,$2) returning id, name, score, created_at",
          [data.name, data.score]
        );
        ws.send(JSON.stringify({ ok: true, score: rows[0] }));
        await broadcastTop();

      } else if (msg?.type === "get_top") {
        const top = await getTop(msg.n ?? 10);
        ws.send(JSON.stringify({ type: "top", data: top }));

      } else {
        ws.send(JSON.stringify({ ok: false, error: "payload inválido" }));
      }
    } catch (e) {
      console.error("WS msg error:", e);
      try { ws.send(JSON.stringify({ ok: false, error: String(e) })); } catch {}
    }
  });

  ws.on("close", () => console.log("❌ WS puro desconectado"));

  try { ws.send(JSON.stringify({ type: "hello", msg: "conectado" })); } catch {}
});

// --- Utils compartidas ---
async function getTop(n = 10) {
  n = Math.min(Math.max(parseInt(n, 10) || 10, 1), 200);
  const { rows } = await pool.query(
    "select id, name, score, created_at from scores order by score desc, id asc limit $1",
    [n]
  );
  return rows;
}

async function broadcastTop() {
  const top = await getTop(10);
  // Web (Socket.IO)
  io.emit("top_updated", top);
  // WS puro (Unity)
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      try { client.send(JSON.stringify({ type: "top_updated", data: top })); } catch {}
    }
  }
}

// --- Arranque / cierre ---
server.listen(PORT, HOST, () => {
  console.log(`Servidor escuchando en http://${HOST}:${PORT}`);
});
