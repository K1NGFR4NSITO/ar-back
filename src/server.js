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
app.use(cors({ origin: "*" }));          // en prod: restringe a tu dominio/front
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
  // cap de seguridad
  const n = Math.min(Math.max(parseInt(req.query.n ?? "10", 10) || 10, 1), 200);
  const { rows } = await pool.query(
    "select id, name, score, created_at from scores order by score desc, id asc limit $1",
    [n]
  );
  res.json(rows);
});

// === CHALLENGES ===
const ChallengeSchema = z.object({
  name: z.string().min(1).max(80),
  points_per_combo: z.number().int().min(0),
  required_count: z.number().int().min(1).max(50),
  duration_minutes: z.number().int().min(1).max(24 * 60),
  fusion_ids: z.array(z.string().min(1)).min(1).max(500),
});

// Seguridad mínima (podrás activarla cuando quieras)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "changeme";

// Crea desafío
app.post("/challenges", async (req, res) => {
  try {
    // Si aun no quieres seguridad, deja esta línea comentada:
    if ((req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }

    const body = ChallengeSchema.parse(req.body);

    const { rows } = await pool.query(
      `INSERT INTO challenges (name, points_per_combo, required_count, expires_at)
       VALUES ($1,$2,$3, NOW() + ($4 || ' minutes')::interval)
       RETURNING id, name, points_per_combo, required_count, expires_at, created_at`,
      [body.name, body.points_per_combo, body.required_count, body.duration_minutes]
    );

    const challengeId = rows[0].id;

    // Inserta fusion_ids
    const values = body.fusion_ids.map((fid, i) => `($1, $${i + 2})`).join(",");
    await pool.query(
      `INSERT INTO challenge_fusions (challenge_id, fusion_id) VALUES ${values}`,
      [challengeId, ...body.fusion_ids]
    );

    // Notifica
    await broadcastChallengeUpdate(challengeId);

    res.json({ ok: true, challenge: rows[0] });
  } catch (e) {
    console.error("POST /challenges", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// Desafío activo
app.get("/challenges/active", async (_req, res) => {
  try {
    const payload = await getActiveChallengePayload();
    res.json(payload);
  } catch (e) {
    console.error("GET /challenges/active", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// Historial simple (poner ANTES de /:id)
app.get("/challenges/history", async (req, res) => {
  try {
    const n = Math.min(Math.max(parseInt(req.query.n ?? "10", 10) || 10, 1), 200);
    const { rows } = await pool.query(
      `SELECT
         c.id, c.name, c.points_per_combo, c.required_count,
         c.expires_at, c.created_at,
         COALESCE(
           json_agg(cf.fusion_id ORDER BY cf.fusion_id)
             FILTER (WHERE cf.fusion_id IS NOT NULL),
           '[]'
         ) AS fusion_ids
       FROM challenges c
       LEFT JOIN challenge_fusions cf ON cf.challenge_id = c.id
       GROUP BY c.id
       ORDER BY c.created_at DESC
       LIMIT $1`,
      [n]
    );
    res.json(rows);
  } catch (e) {
    console.error("GET /challenges/history", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// Listado paginado (poner ANTES de /:id)
app.get("/challenges", async (req, res) => {
  try {
    const limit  = Math.min(Math.max(parseInt(req.query.limit ?? "20", 10) || 20, 1), 200);
    const offset = Math.max(parseInt(req.query.offset ?? "0", 10) || 0, 0);
    const { rows } = await pool.query(
      `SELECT
         c.id, c.name, c.points_per_combo, c.required_count,
         c.expires_at, c.created_at,
         COALESCE(
           json_agg(cf.fusion_id ORDER BY cf.fusion_id)
             FILTER (WHERE cf.fusion_id IS NOT NULL),
           '[]'
         ) AS fusion_ids
       FROM challenges c
       LEFT JOIN challenge_fusions cf ON cf.challenge_id = c.id
       GROUP BY c.id
       ORDER BY c.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    res.json(rows);
  } catch (e) {
    console.error("GET /challenges", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// Detalle por id (poner DESPUÉS de las rutas anteriores)
app.get("/challenges/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ ok: false, error: "invalid_id" });
    }

    const c = await pool.query(
      `SELECT id, name, points_per_combo, required_count, expires_at, created_at
         FROM challenges
        WHERE id = $1`,
      [id]
    );
    if (c.rowCount === 0) return res.status(404).json({ ok: false, error: "not_found" });

    const f = await pool.query(
      `SELECT fusion_id FROM challenge_fusions WHERE challenge_id = $1 ORDER BY fusion_id`,
      [id]
    );
    res.json({ ...c.rows[0], fusion_ids: f.rows.map(r => r.fusion_id) });
  } catch (e) {
    console.error("GET /challenges/:id", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// Borrar desafío
app.delete("/challenges/:id", async (req, res) => {
  try {
    if ((req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ ok: false, error: "invalid_id" });
    }
    await pool.query("DELETE FROM challenges WHERE id = $1", [id]);
    await broadcastChallengeUpdate(null);
    res.json({ ok: true });
  } catch (e) {
    console.error("DELETE /challenges/:id", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// --- helpers de broadcast ---
async function broadcastChallengeUpdate() {
  const payload = await getActiveChallengePayload();
  // web (Socket.IO)
  io.emit("challenge_updated", payload);
  // unity (WS)
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      try { client.send(JSON.stringify({ type: "challenge_updated", data: payload })); } catch {}
    }
  }
}

async function getActiveChallengePayload() {
  const c = await pool.query(
    `SELECT id, name, points_per_combo, required_count, expires_at
       FROM challenges
      WHERE expires_at > NOW()
      ORDER BY expires_at ASC
      LIMIT 1`
  );
  if (c.rowCount === 0) return null;

  const f = await pool.query(
    `SELECT fusion_id FROM challenge_fusions WHERE challenge_id = $1`,
    [c.rows[0].id]
  );
  return { ...c.rows[0], fusion_ids: f.rows.map((r) => r.fusion_id) };
}


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
// Comparte puerto con HTTP/Socket.IO • sin path especial (Unity puede conectarse a wss://…)
const wss = new WebSocketServer({
  server,
  // algunos proxies se llevan mal con perMessageDeflate
  perMessageDeflate: false,
});

// Heartbeat para que Render/proxy no corte la conexión inactiva
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
  ws.on("error", (e) => console.warn("WS error:", e?.message || e));

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

process.on("SIGTERM", () => {
  clearInterval(pingInterval);
  server.close(() => process.exit(0));
});
