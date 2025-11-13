// src/server.js
import express from "express";
import cors from "cors";
import "dotenv/config";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import { WebSocketServer } from "ws";
import { z } from "zod";
import { pool } from "./db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const app = express();

/* ================== CORS + body parsers ================== */
app.use(cors({
  origin: "*", // en prod: restringe a tu dominio
  allowedHeaders: ["Content-Type", "Authorization"],
  methods: ["GET","POST","PATCH","DELETE","OPTIONS"],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: false })); // formularios

/* ================== Health (Render) ================== */
app.get("/health", (_req, res) => res.status(200).send("ok"));

/* ================== Auth helpers ================== */
const JWT_SECRET = process.env.JWT_SECRET || "supersecret-local";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "changeme"; // ya lo usabas para challenges

function signToken(user) {
  // user: { id, username, name, role }
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  const [scheme, token] = auth.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ ok: false, error: "missing_token" });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "invalid_token" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ ok: false, error: "forbidden" });
  }
  next();
}

/* ========= Detección de columnas opcionales en scores ========= */
let HAS_CHALLENGE_ID = false;
let HAS_CLASS = false;

async function detectOptionalColumns() {
  try {
    const q = `
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'scores' AND column_name IN ('challenge_id','class')
    `;
    const { rows } = await pool.query(q);
    const cols = new Set(rows.map(r => r.column_name));
    HAS_CHALLENGE_ID = cols.has("challenge_id");
    HAS_CLASS = cols.has("class");
    console.log("scores columns:", { HAS_CHALLENGE_ID, HAS_CLASS });
  } catch (e) {
    console.warn("No se pudo inspeccionar columnas de scores:", e?.message || e);
  }
}
detectOptionalColumns();

/* ================== Schemas generales ================== */
const SubmitSchema = z.object({
  name: z.string().trim().min(1).max(60),
  score: z.preprocess(v => Number(v), z.number().int().nonnegative()),
  class: z.string().trim().min(1).max(60).optional(),
  challenge_id: z.preprocess(
    v => (v === undefined || v === null || v === "" ? undefined : Number(v)),
    z.number().int().positive().optional()
  ),
});

const ChallengeBase = z.object({
  name: z.string().min(1).max(80),
  points_per_combo: z.number().int().min(0),
  required_count: z.number().int().min(1).max(50),
  fusion_ids: z.array(z.string().min(1)).min(1).max(500),
});
const ChallengeSchema = ChallengeBase.and(
  z.union([
    z.object({ duration_minutes: z.number().int().min(1).max(24 * 60) }),
    z.object({
      expires_at: z.string()
        .refine((v) => !Number.isNaN(Date.parse(v)), "expires_at debe ser ISO válido"),
    }),
  ])
);

/* ================== Schemas de usuarios (login/registro) ================== */

const RegisterDocenteSchema = z.object({
  name: z.string().min(1).max(80),
  username: z.string().min(3).max(40),
  password: z.string().min(6).max(100),
});

const LoginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

const AdminCreateUserSchema = RegisterDocenteSchema.extend({
  role: z.enum(["docente", "admin"]).default("docente"),
  active: z.boolean().optional(), // por defecto true para admin
});

const AdminUpdateUserSchema = z.object({
  name: z.string().min(1).max(80).optional(),
  username: z.string().min(3).max(40).optional(),
  password: z.string().min(6).max(100).optional(),
  role: z.enum(["docente", "admin"]).optional(),
  active: z.boolean().optional(),
});

/* ================== REST: AUTH & USERS ================== */

/**
 * Registro público de DOCENTES.
 * - Crea usuario con role = 'docente' y active = false
 * - El administrador luego podrá activarlos desde /admin/users
 */
app.post("/auth/register-docente", async (req, res) => {
  try {
    const data = RegisterDocenteSchema.parse(req.body);

    // ¿Usuario ya existe?
    const exists = await pool.query(
      "SELECT 1 FROM users WHERE username = $1 LIMIT 1",
      [data.username]
    );
    if (exists.rowCount > 0) {
      return res.status(409).json({ ok: false, error: "username_taken" });
    }

    const hash = await bcrypt.hash(data.password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users (name, username, password, role, active)
       VALUES ($1,$2,$3,'docente', false)
       RETURNING id, name, username, role, active, created_at`,
      [data.name, data.username, hash]
    );

    return res.status(201).json({
      ok: true,
      user: rows[0],
      message: "Cuenta creada. Un administrador debe activarla.",
    });
  } catch (e) {
    console.error("POST /auth/register-docente", e);
    return res.status(400).json({ ok: false, error: String(e) });
  }
});

/**
 * Login genérico (docente / admin).
 * - Rechaza docentes inactivos.
 * - Devuelve JWT + datos básicos.
 */
app.post("/auth/login", async (req, res) => {
  try {
    const data = LoginSchema.parse(req.body);

    const result = await pool.query(
      `SELECT id, name, username, password, role, active, created_at
         FROM users
        WHERE username = $1
        LIMIT 1`,
      [data.username]
    );

    if (result.rowCount === 0) {
      return res.status(400).json({ ok: false, error: "invalid_credentials" });
    }

    const user = result.rows[0];

    // Primero intentar comparar como hash bcrypt
    let passwordOk = false;
    try {
      passwordOk = await bcrypt.compare(data.password, user.password);
    } catch {
      passwordOk = false;
    }

    // Fallback: por si tu admin viejo está en texto plano
    if (!passwordOk && data.password === user.password) {
      passwordOk = true;
    }

    if (!passwordOk) {
      return res.status(400).json({ ok: false, error: "invalid_credentials" });
    }

    if (user.role === "docente" && !user.active) {
      return res.status(403).json({
        ok: false,
        error: "inactive_account",
        message: "Un administrador debe activar tu cuenta.",
      });
    }

    const publicUser = {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role,
      active: user.active,
      created_at: user.created_at,
    };

    const token = signToken(publicUser);

    return res.json({ ok: true, token, user: publicUser });
  } catch (e) {
    console.error("POST /auth/login", e);
    return res.status(400).json({ ok: false, error: String(e) });
  }
});

/**
 * Info del perfil logueado (para el front).
 */
app.get("/auth/me", authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, username, role, active, created_at
         FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ ok: false, error: "not_found" });
    }
    return res.json({ ok: true, user: result.rows[0] });
  } catch (e) {
    console.error("GET /auth/me", e);
    return res.status(400).json({ ok: false, error: String(e) });
  }
});

/* ================== ADMIN: gestión de usuarios ================== */

/**
 * Listar todos los usuarios (panel admin)
 */
app.get("/admin/users", authRequired, requireAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, username, role, active, created_at
         FROM users
         ORDER BY id ASC`
    );
    return res.json({ ok: true, users: rows });
  } catch (e) {
    console.error("GET /admin/users", e);
    return res.status(400).json({ ok: false, error: String(e) });
  }
});

/**
 * Crear usuario manualmente desde el panel admin
 * (por ejemplo otro admin o un docente ya activo).
 */
app.post("/admin/users", authRequired, requireAdmin, async (req, res) => {
  try {
    const data = AdminCreateUserSchema.parse(req.body);

    const exists = await pool.query(
      "SELECT 1 FROM users WHERE username = $1 LIMIT 1",
      [data.username]
    );
    if (exists.rowCount > 0) {
      return res.status(409).json({ ok: false, error: "username_taken" });
    }

    const hash = await bcrypt.hash(data.password, 10);
    const active = data.active ?? true;

    const { rows } = await pool.query(
      `INSERT INTO users (name, username, password, role, active)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, name, username, role, active, created_at`,
      [data.name, data.username, hash, data.role, active]
    );

    return res.status(201).json({ ok: true, user: rows[0] });
  } catch (e) {
    console.error("POST /admin/users", e);
    return res.status(400).json({ ok: false, error: String(e) });
  }
});

/**
 * Editar usuario (activar/desactivar, cambiar nombre, etc.)
 */
app.patch("/admin/users/:id", authRequired, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ ok: false, error: "invalid_id" });
    }

    const data = AdminUpdateUserSchema.parse(req.body);
    const fields = [];
    const params = [];
    let idx = 1;

    if (data.name !== undefined) {
      fields.push(`name = $${idx++}`);
      params.push(data.name);
    }
    if (data.username !== undefined) {
      fields.push(`username = $${idx++}`);
      params.push(data.username);
    }
    if (data.role !== undefined) {
      fields.push(`role = $${idx++}`);
      params.push(data.role);
    }
    if (data.active !== undefined) {
      fields.push(`active = $${idx++}`);
      params.push(data.active);
    }
    if (data.password !== undefined) {
      const hash = await bcrypt.hash(data.password, 10);
      fields.push(`password = $${idx++}`);
      params.push(hash);
    }

    if (fields.length === 0) {
      return res.status(400).json({ ok: false, error: "nothing_to_update" });
    }

    params.push(id);
    const sql = `
      UPDATE users
         SET ${fields.join(", ")}
       WHERE id = $${idx}
       RETURNING id, name, username, role, active, created_at
    `;

    const { rows } = await pool.query(sql, params);
    if (rows.length === 0) {
      return res.status(404).json({ ok: false, error: "not_found" });
    }

    return res.json({ ok: true, user: rows[0] });
  } catch (e) {
    console.error("PATCH /admin/users/:id", e);
    return res.status(400).json({ ok: false, error: String(e) });
  }
});

/**
 * Eliminar usuario (admin).
 * Puedes evitar que borren al admin principal si quieres.
 */
app.delete("/admin/users/:id", authRequired, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ ok: false, error: "invalid_id" });
    }

    const { rowCount } = await pool.query(
      "DELETE FROM users WHERE id = $1",
      [id]
    );

    if (rowCount === 0) {
      return res.status(404).json({ ok: false, error: "not_found" });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error("DELETE /admin/users/:id", e);
    return res.status(400).json({ ok: false, error: String(e) });
  }
});

/* ================== REST: puntajes ================== */
app.post("/scores", async (req, res) => {
  try {
    const data = SubmitSchema.parse(req.body);

    const cols = ["name", "score"];
    const params = [data.name, data.score];
    let placeholders = ["$1", "$2"];
    let idx = 3;

    if (HAS_CHALLENGE_ID && data.challenge_id !== undefined) {
      cols.push("challenge_id"); params.push(data.challenge_id); placeholders.push(`$${idx++}`);
    }
    if (HAS_CLASS && data.class !== undefined) {
      cols.push("class"); params.push(data.class); placeholders.push(`$${idx++}`);
    }

    const sql = `
      INSERT INTO scores(${cols.join(", ")})
      VALUES (${placeholders.join(", ")})
      RETURNING id, name, score${HAS_CLASS ? ", class" : ""}${HAS_CHALLENGE_ID ? ", challenge_id" : ""}, created_at
    `;
    const { rows } = await pool.query(sql, params);

    await broadcastTop();
    res.json({ ok: true, score: rows[0] });
  } catch (err) {
    console.error("POST /scores error:", err);
    res.status(400).json({ ok: false, error: String(err) });
  }
});

app.get("/scores/top", async (req, res) => {
  const n = Math.min(Math.max(parseInt(req.query.n ?? "10", 10) || 10, 1), 200);
  const { rows } = await pool.query(
    `SELECT id, name, score${HAS_CLASS ? ", class" : ""}${HAS_CHALLENGE_ID ? ", challenge_id" : ""}, created_at
       FROM scores
       ORDER BY score DESC, id ASC
       LIMIT $1`,
    [n]
  );
  res.json(rows);
});

// Resultados por desafío (para el panel web)
app.get("/scores/by_challenge/:id", async (req, res) => {
  try {
    if (!HAS_CHALLENGE_ID) return res.json([]);
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ ok:false, error:"invalid_id" });

    const { rows } = await pool.query(
      `SELECT id, name, score${HAS_CLASS ? ", class" : ""}, created_at
         FROM scores
        WHERE challenge_id = $1
        ORDER BY score DESC, name ASC`,
      [id]
    );
    res.json(rows.map(r => ({
      id: r.id, name: r.name, score: r.score,
      class: HAS_CLASS ? r.class : undefined, created_at: r.created_at,
    })));
  } catch (e) {
    console.error("GET /scores/by_challenge/:id", e);
    res.status(400).json({ ok:false, error:String(e) });
  }
});

app.get("/scores/by_challenge", async (req, res) => {
  try {
    if (!HAS_CHALLENGE_ID) return res.json([]);
    const id = Number(req.query.challenge_id);
    if (!Number.isInteger(id)) return res.status(400).json({ ok:false, error:"invalid_id" });

    const { rows } = await pool.query(
      `SELECT id, name, score${HAS_CLASS ? ", class" : ""}, created_at
         FROM scores
        WHERE challenge_id = $1
        ORDER BY score DESC, name ASC`,
      [id]
    );
    res.json(rows.map(r => ({
      id: r.id, name: r.name, score: r.score,
      class: HAS_CLASS ? r.class : undefined, created_at: r.created_at,
    })));
  } catch (e) {
    console.error("GET /scores/by_challenge", e);
    res.status(400).json({ ok:false, error:String(e) });
  }
});

/* ================== CHALLENGES ================== */
app.post("/challenges", async (req, res) => {
  try {
    if ((req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }
    const body = ChallengeSchema.parse(req.body);

    let expiresClause;
    let params;
    if ("duration_minutes" in body) {
      expiresClause = "NOW() + ($4 || ' minutes')::interval";
      params = [body.name, body.points_per_combo, body.required_count, body.duration_minutes];
    } else {
      expiresClause = "$4::timestamptz";
      params = [body.name, body.points_per_combo, body.required_count, body.expires_at];
    }

    const { rows } = await pool.query(
      `INSERT INTO challenges (name, points_per_combo, required_count, expires_at)
       VALUES ($1,$2,$3, ${expiresClause})
       RETURNING id, name, points_per_combo, required_count, expires_at, created_at`,
      params
    );

    const challengeId = rows[0].id;

    const values = body.fusion_ids.map((_, i) => `($1, $${i + 2})`).join(",");
    await pool.query(
      `INSERT INTO challenge_fusions (challenge_id, fusion_id) VALUES ${values}`,
      [challengeId, ...body.fusion_ids]
    );

    await broadcastChallengeUpdate(challengeId);
    res.json({ ok: true, challenge: rows[0] });
  } catch (e) {
    console.error("POST /challenges", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

app.get("/challenges/active", async (_req, res) => {
  try {
    const payload = await getActiveChallengePayload();
    res.json(payload);
  } catch (e) {
    console.error("GET /challenges/active", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

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

app.get("/challenges", async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit ?? "20", 10) || 20, 1), 200);
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
    res.json({ ...c.rows[0], fusion_ids: f.rows.map((r) => r.fusion_id) });
  } catch (e) {
    console.error("GET /challenges/:id", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// resultados “preferidos” que usa tu front
app.get("/challenges/:id/results", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ ok:false, error:"invalid_id" });
    if (!HAS_CHALLENGE_ID) return res.json([]);

    const { rows } = await pool.query(
      `SELECT id, name, score${HAS_CLASS ? ", class" : ""}, created_at
         FROM scores
        WHERE challenge_id = $1
        ORDER BY score DESC, name ASC`,
      [id]
    );
    res.json(rows.map(r => ({
      id: r.id, name: r.name, score: r.score,
      class: HAS_CLASS ? r.class : undefined, created_at: r.created_at,
    })));
  } catch (e) {
    console.error("GET /challenges/:id/results", e);
    res.status(400).json({ ok:false, error:String(e) });
  }
});

app.post("/challenges/expire_others", async (req, res) => {
  try {
    if ((req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }
    const keepId = Number(req.body?.keep_id) || null;

    if (keepId) {
      await pool.query(
        "UPDATE challenges SET expires_at = NOW() - interval '1 second' WHERE id <> $1 AND expires_at > NOW()",
        [keepId]
      );
    } else {
      await pool.query(
        "UPDATE challenges SET expires_at = NOW() - interval '1 second' WHERE expires_at > NOW()"
      );
    }
    await broadcastChallengeUpdate();
    res.json({ ok: true });
  } catch (e) {
    console.error("POST /challenges/expire_others", e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

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

/* ================== helpers broadcast ================== */
async function broadcastChallengeUpdate() {
  const payload = await getActiveChallengePayload();
  io.emit("challenge_updated", payload);           // web (Socket.IO)
  for (const client of wss.clients) {              // unity (WS)
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

/* ================== HTTP + sockets ================== */
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);

// *** CREAR EL SERVER UNA SOLA VEZ ***
const server = http.createServer(app);

// Socket.IO (web)
const io = new SocketIOServer(server, { cors: { origin: "*" } });

io.on("connection", (socket) => {
  console.log("✅ socket conectado:", socket.id);

  socket.on("get_top", async (n = 10) => {
    const top = await getTop(n);
    socket.emit("top", top);
  });

  socket.on("submit_score", async (payload, cb) => {
    try {
      const data = SubmitSchema.parse(payload);

      const cols = ["name", "score"];
      const params = [data.name, data.score];
      let placeholders = ["$1", "$2"];
      let idx = 3;

      if (HAS_CHALLENGE_ID && data.challenge_id !== undefined) {
        cols.push("challenge_id"); params.push(data.challenge_id); placeholders.push(`$${idx++}`);
      }
      if (HAS_CLASS && data.class !== undefined) {
        cols.push("class"); params.push(data.class); placeholders.push(`$${idx++}`);
      }

      const sql = `
        INSERT INTO scores(${cols.join(", ")})
        VALUES (${placeholders.join(", ")})
        RETURNING id, name, score${HAS_CLASS ? ", class" : ""}${HAS_CHALLENGE_ID ? ", challenge_id" : ""}, created_at
      `;
      const { rows } = await pool.query(sql, params);

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

// WebSocket puro (Unity) en el mismo puerto
const wss = new WebSocketServer({ server, perMessageDeflate: false });
wss.on("headers", () => {});


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
        const data = SubmitSchema.parse({
          name: msg.name, score: msg.score, class: msg.class, challenge_id: msg.challenge_id
        });

        const cols = ["name", "score"];
        const params = [data.name, data.score];
        let placeholders = ["$1", "$2"];
        let idx = 3;

        if (HAS_CHALLENGE_ID && data.challenge_id !== undefined) {
          cols.push("challenge_id"); params.push(data.challenge_id); placeholders.push(`$${idx++}`);
        }
        if (HAS_CLASS && data.class !== undefined) {
          cols.push("class"); params.push(data.class); placeholders.push(`$${idx++}`);
        }

        const sql = `
          INSERT INTO scores(${cols.join(", ")})
          VALUES (${placeholders.join(", ")})
          RETURNING id, name, score${HAS_CLASS ? ", class" : ""}${HAS_CHALLENGE_ID ? ", challenge_id" : ""}, created_at
        `;
        const { rows } = await pool.query(sql, params);

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

/* ================== Utils ================== */
async function getTop(n = 10) {
  n = Math.min(Math.max(parseInt(n, 10) || 10, 1), 200);
  const { rows } = await pool.query(
    `SELECT id, name, score${HAS_CLASS ? ", class" : ""}${HAS_CHALLENGE_ID ? ", challenge_id" : ""}, created_at
       FROM scores
       ORDER BY score DESC, id ASC
       LIMIT $1`,
    [n]
  );
  return rows;
}

async function broadcastTop() {
  const top = await getTop(10);
  io.emit("top_updated", top); // web (Socket.IO)
  for (const client of wss.clients) { // unity (WS)
    if (client.readyState === 1) {
      try { client.send(JSON.stringify({ type: "top_updated", data: top })); } catch {}
    }
  }
}

/* ================== Arranque ================== */
server.listen(PORT, HOST, () => {
  console.log(`Servidor escuchando en http://${HOST}:${PORT}`);
});

process.on("SIGTERM", () => {
  clearInterval(pingInterval);
  server.close(() => process.exit(0));
});
