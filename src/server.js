// src/server.js
import express from "express";
import cors from "cors";
import "dotenv/config";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import { WebSocketServer } from "ws";           // ← WS puro
import { z } from "zod";
import { pool } from "./db.js";

const app = express();
app.use(cors({ origin: "*" }));                 // en prod: limita tu dominio
app.use(express.json());

// ---------------- REST (pruebas / fallback) ----------------
app.post("/scores", async (req, res) => {
  try {
    const schema = z.object({
      name: z.string().min(1).max(60),
      score: z.number().int().nonnegative(),
    });
    const data = schema.parse(req.body);

    const { rows } = await pool.query(
      "insert into scores(name, score) values ($1,$2) returning id, name, score, created_at",
      [data.name, data.score]
    );

    broadcastTop().catch(console.error);
    res.json({ ok: true, score: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(400).json({ ok: false, error: String(err) });
  }
});

app.get("/scores/top", async (req, res) => {
  const n = Math.min(parseInt(req.query.n ?? "10", 10) || 10, 50);
  const { rows } = await pool.query(
    "select id, name, score, created_at from scores order by score desc, id asc limit $1",
    [n]
  );
  res.json(rows);
});

// ---------------- HTTP base ----------------
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const server = http.createServer(app);

// ---------------- Socket.IO (para web) ----------------
const io = new SocketIOServer(server, { cors: { origin: "*" } }); // prod: restringe

const SubmitSchema = z.object({
  name: z.string().min(1).max(60),
  score: z.number().int().nonnegative(),
});

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

// ---------------- WebSocket puro (para Unity) ----------------
const wss = new WebSocketServer({ server });    // comparte el mismo puerto 3000

wss.on("connection", (ws, req) => {
  console.log("✅ WS puro conectado:", req.socket.remoteAddress);

  ws.on("message", async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      // Espera: { type:"score", name:"Ernesto", score:123 }
      if (msg?.type === "score" && typeof msg.name === "string" && Number.isInteger(msg.score)) {
        const { rows } = await pool.query(
          "insert into scores(name, score) values ($1,$2) returning id, name, score, created_at",
          [msg.name, msg.score]
        );
        ws.send(JSON.stringify({ ok: true, score: rows[0] }));
        broadcastTop().catch(console.error);
      } else if (msg?.type === "get_top") {
        const top = await getTop(10);
        ws.send(JSON.stringify({ type: "top", data: top }));
      } else {
        ws.send(JSON.stringify({ ok: false, error: "payload inválido" }));
      }
    } catch (e) {
      console.error("WS msg error:", e);
      ws.send(JSON.stringify({ ok: false, error: String(e) }));
    }
  });

  ws.on("close", () => {
    console.log("❌ WS puro desconectado");
  });

  ws.send(JSON.stringify({ type: "hello", msg: "conectado" }));
});

// ---------------- Utils compartidas ----------------
async function getTop(n = 10) {
  n = Math.min(parseInt(n, 10) || 10, 50);
  const { rows } = await pool.query(
    "select id, name, score, created_at from scores order by score desc, id asc limit $1",
    [n]
  );
  return rows;
}

async function broadcastTop() {
  const top = await getTop(10);
  io.emit("top_updated", top); // web por Socket.IO
  // opcional: también podrías iterar los clientes WS puros y enviarles
  // for (const client of wss.clients) if (client.readyState === 1) client.send(JSON.stringify({ type:"top_updated", data: top }));
}

server.listen(PORT, HOST, () => {
  console.log(`Servidor escuchando en http://${HOST}:${PORT}`);
});
